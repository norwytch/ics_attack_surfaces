"""Tests for the asset loader + graph and the mapping rule engine."""
import os

import pytest

from ics_modeler.assets import Architecture, Asset, PurdueLevel, load_architecture
from ics_modeler.mapping import (
    load_rules,
    map_architecture,
    rule_matches,
    validate_rules_against_attack,
)

ATTACK_PATH = "data/attack_ics.json"
ARCHES = ["data/reference_architecture.yaml", "data/water_treatment.yaml"]
OT_PROTOCOLS = {"Modbus", "DNP3", "EtherNet/IP", "S7comm"}

ARCH_PATH = "data/reference_architecture.yaml"
RULES_PATH = "data/mapping_rules.yaml"


def test_architecture_loads_and_validates():
    arch = load_architecture(ARCH_PATH)
    assert isinstance(arch, Architecture)
    assert arch.assets
    # entry/target nodes resolve to real assets
    for n in arch.entry_nodes + arch.target_nodes:
        assert n in arch.assets


def test_graph_is_connected_to_targets():
    import networkx as nx

    arch = load_architecture(ARCH_PATH)
    g = arch.graph()
    # every target must be reachable from at least one entry node
    for target in arch.target_nodes:
        assert any(nx.has_path(g, e, target) for e in arch.entry_nodes)


@pytest.mark.parametrize("arch_path", ARCHES)
def test_every_reference_architecture_loads(arch_path):
    arch = load_architecture(arch_path)
    assert arch.assets and arch.entry_nodes and arch.target_nodes


@pytest.mark.parametrize("arch_path", ARCHES)
def test_ot_assets_are_never_left_uncovered(arch_path):
    # generalization guard: any asset speaking an unauthenticated OT protocol must
    # map to at least one technique, regardless of which protocol/vendor it uses.
    arch = load_architecture(arch_path)
    mapped = map_architecture(arch, load_rules(RULES_PATH))
    for name, a in arch.assets.items():
        if OT_PROTOCOLS & set(a.protocols):
            assert mapped[name]["techniques"], (
                f"{name} speaks an OT protocol ({a.protocols}) but got no techniques"
            )


def test_unresolved_connection_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "entry_nodes: [a]\n"
        "target_nodes: [a]\n"
        "assets:\n"
        "  - name: a\n"
        "    level: L1_CONTROL\n"
        "    component_type: PLC\n"
        "    connections: [ghost]\n"
    )
    with pytest.raises(ValueError, match="unknown asset"):
        load_architecture(str(bad))


def test_rule_matches_list_and_scalar():
    asset = Asset(
        name="plc", level=PurdueLevel.L1_CONTROL, component_type="PLC",
        protocols=["Modbus"], authenticated=False, exposed_interfaces=["network"],
    )
    assert rule_matches(asset, {"protocols": ["Modbus"], "authenticated": False})
    assert rule_matches(asset, {"component_type": "PLC"})
    assert not rule_matches(asset, {"protocols": ["DNP3"]})
    assert not rule_matches(asset, {"authenticated": True})


def test_map_architecture_attaches_techniques():
    arch = load_architecture(ARCH_PATH)
    rules = load_rules(RULES_PATH)
    mapped = map_architecture(arch, rules)
    # find an unauthenticated Modbus PLC generically rather than hardcoding a name,
    # so renaming assets in the data file doesn't break the test with a bare KeyError
    plcs = [
        name for name, a in arch.assets.items()
        if a.component_type == "PLC" and "Modbus" in a.protocols and not a.authenticated
    ]
    assert plcs, "fixture should contain an unauthenticated Modbus PLC"
    for name in plcs:
        ids = {t["id"] for t in mapped[name]["techniques"]}
        assert "T1692.001" in ids   # Command Message (was T0855, revoked)


def test_load_rules_rejects_unknown_when_field(tmp_path):
    bad = tmp_path / "rules.yaml"
    bad.write_text(  # `protocol` is a typo for `protocols`
        "rules:\n"
        "  - id: typo-rule\n"
        "    when:\n"
        "      protocol: [Modbus]\n"
        "    techniques: [T0855]\n"
    )
    with pytest.raises(ValueError, match="unknown asset field"):
        load_rules(str(bad))


@pytest.mark.skipif(
    not os.path.exists(ATTACK_PATH),
    reason="ATT&CK bundle not downloaded (run data_sources.fetch_attack_ics())",
)
def test_rules_reference_current_techniques():
    from ics_modeler.data_sources import load_attack_ics

    attack = load_attack_ics(ATTACK_PATH)
    rules = load_rules(RULES_PATH)
    stale = validate_rules_against_attack(rules, attack)
    assert stale == {}, f"rules reference non-current technique IDs: {stale}"


def test_load_architecture_rejects_float_version(tmp_path):
    bad = tmp_path / "arch.yaml"
    bad.write_text(  # unquoted 3.20 -> float 3.2, would silently truncate
        "entry_nodes: [a]\n"
        "target_nodes: [a]\n"
        "assets:\n"
        "  - name: a\n"
        "    level: L1_CONTROL\n"
        "    component_type: PLC\n"
        "    version: 3.20\n"
        "    connections: []\n"
    )
    with pytest.raises(ValueError, match="version must be quoted"):
        load_architecture(str(bad))
