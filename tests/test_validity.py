"""Tests for the validity-experiment measurement instrument (Kendall's tau-b)."""
from experiments.validity import kendall_tau_b, top_k_overlap


def test_tau_perfect_agreement():
    assert kendall_tau_b([1, 2, 3, 4], [10, 20, 30, 40]) == 1.0


def test_tau_perfect_reversal():
    assert kendall_tau_b([1, 2, 3, 4], [40, 30, 20, 10]) == -1.0


def test_tau_independent_is_near_zero():
    # one swap in a 4-item list -> 5 concordant, 1 discordant -> tau ~ 0.67
    tau = kendall_tau_b([1, 2, 3, 4], [1, 2, 4, 3])
    assert 0.6 < tau < 0.7


def test_tau_handles_ties():
    # y is all ties -> denominator guards against div-by-zero, returns 0
    assert kendall_tau_b([1, 2, 3], [5, 5, 5]) == 0.0


def test_top_k_overlap():
    a = {"x": 9, "y": 8, "z": 1}
    b = {"x": 9, "y": 8, "z": 1}
    assert top_k_overlap(a, b, 2) == 1.0
    c = {"x": 1, "y": 1, "z": 9}
    assert top_k_overlap(a, c, 1) == 0.0


def test_scale_generator_produces_working_architecture():
    # the synthetic generator must yield a valid architecture the pipeline can analyze
    from experiments.scale import generate
    from ics_modeler.mapping import load_rules, map_architecture
    from ics_modeler.scoring import path_findings, score_architecture

    arch = generate(5)
    assert len(arch.assets) > 50
    mapped = map_architecture(arch, load_rules("data/mapping_rules.yaml"))
    assert any(m["techniques"] for m in mapped.values())
    scores = score_architecture(arch)
    paths = path_findings(arch.reachability_graph(), arch.entry_nodes, arch.target_nodes, scores)
    assert paths  # entry reaches the targets through the hierarchy


def test_criterion_ukraine_flags_documented_root_cause():
    # guards the criterion-validity headline: the tool independently flags the VPN IT->OT
    # bypass that the 2015 Ukraine report identified as the root cause.
    from ics_modeler.assets import load_architecture
    from ics_modeler.scoring import segmentation_violations

    arch = load_architecture("experiments/ukraine_2015.yaml")
    viols = {(v["from"], v["to"]) for v in segmentation_violations(arch)}
    assert ("vpn_gateway", "scada_dms_server") in viols
