"""Tests for threat-trend correlation, the briefing, and the pipeline."""
import os

import pytest

from ics_modeler.assets import load_architecture
from ics_modeler.mapping import load_rules, map_architecture, validate_rules_against_attack
from ics_modeler.pipeline import build
from ics_modeler.report import generate_briefing, plot_risk_matrix
from ics_modeler.scoring import chokepoints, path_findings, score_architecture
from ics_modeler.trends import load_campaigns, map_campaigns_to_exposure

ARCH_PATH = "data/reference_architecture.yaml"
RULES_PATH = "data/mapping_rules.yaml"
TRENDS_PATH = "data/threat_trends.yaml"
ATTACK_PATH = "data/attack_ics.json"


def _mapped():
    arch = load_architecture(ARCH_PATH)
    return arch, map_architecture(arch, load_rules(RULES_PATH))


def test_campaign_correlation_matches_shared_techniques():
    arch, mapped = _mapped()
    campaigns = [
        {"id": "c1", "name": "C1", "techniques": ["T0843"]},   # Program Download
        {"id": "c2", "name": "C2", "techniques": ["T9999"]},   # nonexistent -> no match
    ]
    out = map_campaigns_to_exposure(mapped, campaigns)
    by_id = {c["id"]: c for c in out}
    # interlocking_controller has S7comm -> T0843; should be flagged for C1
    c1_assets = {m["asset"] for m in by_id["c1"]["matches"]}
    assert "interlocking_controller" in c1_assets
    assert by_id["c2"]["matches"] == []
    # sorted by coverage (strongest first)
    assert out[0]["id"] == "c1"


def test_campaign_confidence_reflects_coverage():
    arch, mapped = _mapped()
    # single exposed technique -> full coverage, High confidence
    full = map_campaigns_to_exposure(mapped, [{"id": "f", "name": "F",
                                               "techniques": ["T0843"]}])[0]
    assert full["coverage"] == 1.0 and full["confidence"] == "High"
    # 1 of 5 techniques exposed -> low coverage, demoted to Low confidence
    partial = map_campaigns_to_exposure(mapped, [{"id": "p", "name": "P",
        "techniques": ["T0843", "T9990", "T9991", "T9992", "T9993"]}])[0]
    assert partial["coverage"] == 0.2 and partial["confidence"] == "Low"


@pytest.mark.skipif(
    not os.path.exists(ATTACK_PATH),
    reason="ATT&CK bundle not downloaded (run data_sources.fetch_attack_ics())",
)
def test_campaign_techniques_are_current():
    from ics_modeler.data_sources import load_attack_ics

    attack = load_attack_ics(ATTACK_PATH)
    campaigns = load_campaigns(TRENDS_PATH)
    # validate_rules_against_attack works on any {techniques: [...]} list
    stale = validate_rules_against_attack(campaigns, attack)
    assert stale == {}, f"threat_trends references non-current technique IDs: {stale}"


@pytest.mark.skipif(
    not os.path.exists(ATTACK_PATH),
    reason="ATT&CK bundle not downloaded (run data_sources.fetch_attack_ics())",
)
def test_attack_mitigations_loaded_and_grounded(tmp_path):
    from ics_modeler.data_sources import load_attack_mitigations

    mits = load_attack_mitigations(ATTACK_PATH)
    assert mits, "expected technique -> mitigation mappings"
    assert "T0843" in mits and mits["T0843"]          # Program Download has mitigations
    assert all(m["id"].startswith("M") for m in mits["T0843"])

    arch, mapped = _mapped()
    g = arch.graph()
    scores = score_architecture(arch, g)
    paths = path_findings(g, arch.entry_nodes, arch.target_nodes, scores)
    text = generate_briefing(arch, mapped, scores, paths, chokepoints(g),
                             map_campaigns_to_exposure(mapped, []), [], mits, None,
                             str(tmp_path / "b.md"))
    assert "ATT&CK-grounded mitigations" in text


def test_generate_briefing_has_core_sections(tmp_path):
    arch, mapped = _mapped()
    g = arch.graph()
    scores = score_architecture(arch, g)
    paths = path_findings(g, arch.entry_nodes, arch.target_nodes, scores)
    chokes = chokepoints(g)
    campaigns = map_campaigns_to_exposure(mapped, [])
    dest = tmp_path / "briefing.md"
    text = generate_briefing(arch, mapped, scores, paths, chokes, campaigns, [], None, None,
                             str(dest))
    for heading in ("Executive summary", "Asset inventory", "Attack-path findings",
                    "Segmentation findings", "Threat-trend mapping",
                    "mitigation recommendations", "Scope & limitations"):
        assert heading in text
    assert dest.exists()


def test_plot_writes_png(tmp_path):
    arch = load_architecture(ARCH_PATH)
    scores = score_architecture(arch)
    dest = tmp_path / "risk.png"
    plot_risk_matrix(scores, str(dest))
    assert dest.exists() and dest.stat().st_size > 0


def test_pipeline_build_offline(tmp_path):
    build(out_dir=str(tmp_path), fetch_cves=False)
    assert (tmp_path / "briefing.md").exists()
    assert (tmp_path / "figures" / "network.png").exists()
    assert (tmp_path / "figures" / "risk_matrix.png").exists()
    assert "Vulnerability Briefing" in (tmp_path / "briefing.md").read_text()


def test_pipeline_build_second_architecture(tmp_path):
    # the framework must run end-to-end on a structurally different model unchanged
    build(arch_path="data/water_treatment.yaml", out_dir=str(tmp_path), fetch_cves=False)
    briefing = (tmp_path / "briefing.md").read_text()
    assert "Water Treatment" in briefing
    assert (tmp_path / "figures" / "network.png").exists()


def test_version_status_filters_by_version():
    from ics_modeler.data_sources import _version_status

    base = "cpe:2.3:o:siemens:simatic"
    cve = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:o:siemens:simatic:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "3.0"}]}]}]}
    assert _version_status("2.9", cve, base) == "confirmed"      # 2.9 < 3.0
    assert _version_status("3.5", cve, base) == "not-affected"   # 3.5 >= 3.0
    assert _version_status("", cve, base) == "unconfirmed"       # no asset version


def test_cve_snapshot_present_and_nonempty():
    from ics_modeler.data_sources import load_cve_snapshot

    snap = load_cve_snapshot()
    assert snap, "committed CVE snapshot empty — run python -m scripts.build_cve_snapshot"
    assert any(cves for cves in snap.values()), "snapshot has no CVEs for any product"


def test_default_offline_briefing_shows_real_cves(tmp_path):
    # the flagship feature must work WITHOUT --cves, via the committed snapshot
    build(arch_path="data/water_treatment.yaml", out_dir=str(tmp_path), fetch_cves=False)
    briefing = (tmp_path / "briefing.md").read_text()
    assert "CVE-" in briefing, "default briefing should attach real CVEs from the snapshot"
