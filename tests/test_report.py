"""Tests for threat-trend correlation, the briefing, and the pipeline."""
import os

import pytest

from src.assets import load_architecture
from src.mapping import load_rules, map_architecture, validate_rules_against_attack
from src.pipeline import build
from src.report import generate_briefing, plot_risk_matrix
from src.scoring import chokepoints, path_findings, score_architecture
from src.trends import load_campaigns, map_campaigns_to_exposure

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
    # sorted most-hit first
    assert out[0]["id"] == "c1"


@pytest.mark.skipif(
    not os.path.exists(ATTACK_PATH),
    reason="ATT&CK bundle not downloaded (run data_sources.fetch_attack_ics())",
)
def test_campaign_techniques_are_current():
    from src.data_sources import load_attack_ics

    attack = load_attack_ics(ATTACK_PATH)
    campaigns = load_campaigns(TRENDS_PATH)
    # validate_rules_against_attack works on any {techniques: [...]} list
    stale = validate_rules_against_attack(campaigns, attack)
    assert stale == {}, f"threat_trends references non-current technique IDs: {stale}"


def test_generate_briefing_has_core_sections(tmp_path):
    arch, mapped = _mapped()
    g = arch.graph()
    scores = score_architecture(arch, g)
    paths = path_findings(g, arch.entry_nodes, arch.target_nodes, scores)
    chokes = chokepoints(g)
    campaigns = map_campaigns_to_exposure(mapped, [])
    dest = tmp_path / "briefing.md"
    text = generate_briefing(arch, mapped, scores, paths, chokes, campaigns, str(dest))
    for heading in ("Executive summary", "Asset inventory", "Attack-path findings",
                    "Threat-trend mapping", "mitigation recommendations"):
        assert heading in text
    assert dest.exists()


def test_plot_writes_png(tmp_path):
    arch = load_architecture(ARCH_PATH)
    scores = score_architecture(arch)
    dest = tmp_path / "risk.png"
    plot_risk_matrix(scores, str(dest))
    assert dest.exists() and dest.stat().st_size > 0


def test_pipeline_build_offline(tmp_path):
    dest = build(out_dir=str(tmp_path), fetch_cves=False)
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
