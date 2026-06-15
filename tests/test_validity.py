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
