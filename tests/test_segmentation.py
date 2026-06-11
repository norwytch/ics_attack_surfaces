"""Tests for segmentation-aware reachability and attack paths (roadmap item #2)."""
from src.assets import Architecture, Asset, PurdueLevel, Segmentation, load_architecture
from src.scoring import attack_paths, segmentation_violations


def _mini(policy: Segmentation) -> Architecture:
    """ext(L4) — mid(L2) — target(L1); ext reaches mid directly across the IT/OT line."""
    assets = {
        "ext": Asset("ext", PurdueLevel.L4_ENTERPRISE, "workstation",
                     protocols=["RDP"], connections=["mid"]),
        "mid": Asset("mid", PurdueLevel.L2_SUPERVISORY, "SCADA_server",
                     protocols=["OPC"], connections=["ext", "target"]),
        "target": Asset("target", PurdueLevel.L1_CONTROL, "PLC",
                        protocols=["Modbus"], connections=["mid"]),
    }
    return Architecture(assets=assets, entry_nodes=["ext"], target_nodes=["target"],
                        segmentation=policy)


def test_open_policy_allows_path():
    arch = _mini(Segmentation())  # default allow, no boundaries
    paths = attack_paths(arch.reachability_graph(), arch.entry_nodes, arch.target_nodes)
    assert paths, "with no firewall the external path should reach the target"


def test_deny_boundary_blocks_path():
    blocked = Segmentation(boundaries=[
        {"zones": frozenset({"L4_ENTERPRISE", "L2_SUPERVISORY"}), "allow": set()},
    ])
    arch = _mini(blocked)
    paths = attack_paths(arch.reachability_graph(), arch.entry_nodes, arch.target_nodes)
    assert not paths, "a deny rule at the IT/OT boundary should remove the only path"


def test_removing_the_rule_restores_the_path():
    # same topology, with vs. without the deny rule -> different attack-path set
    blocked = _mini(Segmentation(boundaries=[
        {"zones": frozenset({"L4_ENTERPRISE", "L2_SUPERVISORY"}), "allow": set()}]))
    opened = _mini(Segmentation())
    assert not attack_paths(blocked.reachability_graph(), ["ext"], ["target"])
    assert attack_paths(opened.reachability_graph(), ["ext"], ["target"])


def test_violation_flagged_in_water_not_transit():
    water = load_architecture("data/water_treatment.yaml")
    transit = load_architecture("data/reference_architecture.yaml")
    wv = segmentation_violations(water)
    assert any(v["from"] == "remote_access_host" and v["to"] == "scada_server" for v in wv)
    # the transit plant is properly segmented — no direct IT->OT edges
    assert segmentation_violations(transit) == []
