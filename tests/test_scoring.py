"""Tests for NIST 800-30 scoring and attack-path findings."""
from src.assets import load_architecture
from src.scoring import (
    BAND_ORDER,
    band,
    path_findings,
    risk_band,
    score_architecture,
    score_impact,
    score_likelihood,
)

ARCH_PATH = "data/reference_architecture.yaml"


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


def test_known_exploited_cve_raises_likelihood():
    arch = load_architecture(ARCH_PATH)
    g = arch.graph()
    plc = arch.assets["wayside_plc"]
    base = score_likelihood(plc, g, arch.entry_nodes, cves=None)
    kev = score_likelihood(
        plc, g, arch.entry_nodes,
        cves=[{"id": "CVE-x", "cvss": 9.8, "known_exploited": True}],
    )
    assert kev > base


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
