"""Tests for IEC 62443 zone mapping and ATT&CK Navigator layer export."""
import json

from ics_modeler.assets import load_architecture
from ics_modeler.frameworks import iec62443_zones, navigator_layer, write_navigator_layer
from ics_modeler.mapping import load_rules, map_architecture

ARCH = "data/water_treatment.yaml"
RULES = "data/mapping_rules.yaml"


def _mapped():
    arch = load_architecture(ARCH)
    return arch, map_architecture(arch, load_rules(RULES))


def test_navigator_layer_is_a_valid_ics_layer():
    arch, mapped = _mapped()
    layer = navigator_layer(arch, mapped)
    assert layer["domain"] == "ics-attack"
    assert layer["versions"]["layer"]          # Navigator needs a layer-format version
    assert layer["techniques"], "expected exposed techniques"
    for t in layer["techniques"]:              # required per-technique fields
        assert t["techniqueID"] and t["score"] >= 1 and "comment" in t
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1692.001" in ids                  # dosing_plc (EtherNet/IP) exposes Command Message


def test_navigator_layer_writes_json(tmp_path):
    arch, mapped = _mapped()
    dest = tmp_path / "layer.json"
    write_navigator_layer(arch, mapped, str(dest))
    assert json.loads(dest.read_text())["domain"] == "ics-attack"


def test_iec62443_zones_group_assets():
    arch = load_architecture(ARCH)
    zones = dict(iec62443_zones(arch))
    assert "business_workstation" in zones["Enterprise Zone"]
    # the dosing PLC sits in a control zone
    assert any("dosing_plc" in names for z, names in zones.items() if "Control" in z)
