"""Tests for NIST 800-30 scoring and attack-path findings."""
import pytest

from ics_modeler.assets import Architecture, Asset, PurdueLevel, load_architecture
from ics_modeler.scoring import (
    BAND_ORDER,
    band,
    path_findings,
    risk_band,
    score_architecture,
    score_impact,
    score_likelihood,
    sensitivity,
)

ARCH_PATH = "data/reference_architecture.yaml"
WATER_PATH = "data/water_treatment.yaml"

# NIST SP 800-30 Rev.1 Table I-2, written out independently of the code's RISK_MATRIX
# so this validates the table rather than re-reading the same constant.
# rows = likelihood band, cols = impact band, both Very Low -> Very High.
_TABLE_I2 = [
    ["Very Low", "Very Low", "Very Low", "Low", "Low"],
    ["Very Low", "Low", "Low", "Low", "Moderate"],
    ["Very Low", "Low", "Moderate", "Moderate", "High"],
    ["Very Low", "Low", "Moderate", "High", "Very High"],
    ["Very Low", "Low", "Moderate", "High", "Very High"],
]
_BAND_CENTERS = [10, 30, 50, 70, 90]  # a representative score inside each band


def _line_graph():
    """entry(L4) — mid(L2) — target(L1), all unauthenticated, no CVEs. Deterministic."""
    assets = {
        "entry": Asset("entry", PurdueLevel.L4_ENTERPRISE, "workstation", connections=["mid"]),
        "mid": Asset("mid", PurdueLevel.L2_SUPERVISORY, "SCADA_server",
                     connections=["entry", "target"]),
        "target": Asset("target", PurdueLevel.L1_CONTROL, "PLC", connections=["mid"]),
    }
    return Architecture(assets=assets, entry_nodes=["entry"], target_nodes=["target"])


def test_risk_matrix_matches_table_i2_all_25_cells():
    for li, lscore in enumerate(_BAND_CENTERS):
        for ii, iscore in enumerate(_BAND_CENTERS):
            assert risk_band(lscore, iscore) == _TABLE_I2[li][ii], (
                f"L={lscore} I={iscore}: got {risk_band(lscore, iscore)}, "
                f"expected {_TABLE_I2[li][ii]}"
            )


def test_score_values_are_pinned():
    # hand-computed from the documented weights/decay; guards against silent drift.
    arch = _line_graph()
    g = arch.graph()
    # likelihood = 0.6*exposure + 0.4*auth(=100, all unauth) ; exposure = 100*0.7^d
    assert score_likelihood(arch.assets["entry"], g, ["entry"]) == 100.0  # d=0 -> 100
    assert score_likelihood(arch.assets["mid"], g, ["entry"]) == 82.0     # d=1 -> 70
    assert score_likelihood(arch.assets["target"], g, ["entry"]) == 69.4  # d=2 -> 49
    # impact = 0.6*criticality + 0.4*blast_radius
    assert score_impact(arch.assets["entry"], g) == 52.0    # crit 20, blast 100
    assert score_impact(arch.assets["mid"], g) == 56.0      # crit 60, blast 50
    assert score_impact(arch.assets["target"], g) == 60.0   # crit 100, blast 0


def test_likelihood_monotonic_in_exposure():
    # closer to the entry node => never lower likelihood (other factors equal)
    arch = _line_graph()
    g = arch.graph()
    le = score_likelihood(arch.assets["entry"], g, ["entry"])
    lm = score_likelihood(arch.assets["mid"], g, ["entry"])
    lt = score_likelihood(arch.assets["target"], g, ["entry"])
    assert le >= lm >= lt


def test_authentication_never_raises_likelihood():
    arch = _line_graph()
    g = arch.graph()
    unauth = score_likelihood(arch.assets["mid"], g, ["entry"])
    arch.assets["mid"].authenticated = True
    auth = score_likelihood(arch.assets["mid"], g, ["entry"])
    assert auth < unauth


def test_bands_cover_full_range():
    assert band(0) == "Very Low"
    assert band(50) == "Moderate"
    assert band(100) == "Very High"
    assert band(150) == "Very High"   # out-of-range still resolves


def test_risk_matrix_table_i2_cells():
    # spot-check known NIST 800-30 Table I-2 cells
    assert risk_band(85, 85) == "Very High"   # High/VH x High/VH
    assert risk_band(50, 90) == "High"        # Moderate likelihood x Very High impact
    assert risk_band(10, 90) == "Low"         # Very Low likelihood x Very High impact
    assert risk_band(10, 10) == "Very Low"


def test_scores_in_range_and_band_consistent():
    arch = load_architecture(ARCH_PATH)
    scores = score_architecture(arch)
    assert set(scores) == set(arch.assets)
    for s in scores.values():
        for key in ("likelihood", "impact"):
            assert 0 <= s[key] <= 100
        assert s["band"] in BAND_ORDER
        assert 0 <= s["severity"] <= 4
        # band is the matrix lookup of the two dimensions
        assert s["band"] == risk_band(s["likelihood"], s["impact"])


def test_target_plc_has_high_impact():
    arch = load_architecture(ARCH_PATH)
    g = arch.graph()
    # an L1 control PLC affects the process directly -> impact should outrank enterprise IT
    plc = arch.assets["wayside_plc"]
    workstation = arch.assets["enterprise_workstation"]
    assert score_impact(plc, g) > score_impact(workstation, g)


def test_kev_escalates_risk_band():
    # a KEV (actively-exploited) CVE bumps the asset's risk band up one level.
    arch = load_architecture(ARCH_PATH)
    target = "wayside_plc"
    base = score_architecture(arch, cves_by_asset={})[target]
    esc = score_architecture(
        arch, cves_by_asset={target: [{"id": "CVE-x", "known_exploited": True}]}
    )[target]
    assert esc["kev_escalated"] is True
    assert esc["severity"] >= base["severity"]
    if base["severity"] < 4:
        assert esc["severity"] == base["severity"] + 1


def test_high_epss_escalates_band():
    # a top-percentile EPSS CVE escalates even without a KEV listing; below threshold does not.
    arch = load_architecture(ARCH_PATH)
    target = "wayside_plc"
    base = score_architecture(arch, cves_by_asset={})[target]
    hi = score_architecture(arch, cves_by_asset={target: [{"id": "X", "epss_pctl": 0.97}]})[target]
    lo = score_architecture(arch, cves_by_asset={target: [{"id": "Y", "epss_pctl": 0.50}]})[target]
    assert hi["kev_escalated"] is True and hi["severity"] >= base["severity"]
    assert lo["kev_escalated"] is False


@pytest.mark.parametrize("arch_path", [ARCH_PATH, WATER_PATH])
def test_scoring_ranking_is_robust_to_weight_perturbation(arch_path):
    # "Own the scoring": the priority conclusion must not hinge on the exact weights.
    arch = load_architecture(arch_path)
    r = sensitivity(arch, perturb=0.2, top_n=3)
    # the single highest-priority asset is invariant under +/-20% weight perturbation
    assert r["top1_stable_fraction"] == 1.0
    # the top-3 priority set is robust (the decision-relevant output)
    assert r["top_n_set_stable_fraction"] >= 0.8
    # churn is confined to a few near-tied assets, not wild reordering
    assert len(r["top_n_contenders"]) <= r["top_n"] + 2
    # per-asset bands are more weight-sensitive with the 2-factor likelihood, but bounded
    assert r["band_stable_fraction"] >= 0.7


def test_path_findings_reach_targets_shortest_first():
    arch = load_architecture(ARCH_PATH)
    g = arch.graph()
    scores = score_architecture(arch, g)
    findings = path_findings(g, arch.entry_nodes, arch.target_nodes, scores)
    assert findings, "expected at least one external->critical path"
    for f in findings:
        assert f["target"] in arch.target_nodes
    # sorted shortest-first
    lengths = [f["length"] for f in findings]
    assert lengths == sorted(lengths)
