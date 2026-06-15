"""Validity experiment for the risk-ranking model.

Without human experts we cannot test *criterion* validity (agreement with ground-truth
expert judgement). This harness tests what IS computable:

  - Discriminant:  does the full model rank differently from a trivial "Purdue criticality
                   only" baseline, or is the extra machinery decorative?
  - Ablation:      which factors (exposure, auth, blast radius) actually
                   move the ranking when removed?
  - Convergent:    does the model agree with independent lenses it does not directly use
                   (graph betweenness, CVE severity)?
  - Face validity: on the water plant (an Oldsmar-style design) does the chemical-dosing
                   controller rank top and the known remote-access path surface?

Metric: Kendall's tau-b (rank correlation, tie-aware) between per-asset priority scores,
plus top-3 overlap. tau-b = 1 identical order, 0 independent, -1 reversed.

Run: python -m experiments.validity   (writes experiments/RESULTS.md)
"""
from __future__ import annotations

from pathlib import Path

from ics_modeler.assets import load_architecture
from ics_modeler.data_sources import load_cve_snapshot
from ics_modeler.scoring import (
    CRITICALITY_BY_LEVEL,
    IMPACT_WEIGHTS,
    LIKELIHOOD_WEIGHTS,
    chokepoints,
    path_findings,
    score_architecture,
)

ARCHES = {
    "Transit signaling": "data/reference_architecture.yaml",
    "Water treatment": "data/water_treatment.yaml",
}


# --------------------------------------------------------------------------- #
# Measurement instrument (tested in tests/test_validity.py)
# --------------------------------------------------------------------------- #
def kendall_tau_b(x: list[float], y: list[float]) -> float:
    """Tie-aware rank correlation between two score vectors over the same items."""
    n = len(x)
    concordant = discordant = tie_x = tie_y = 0
    for i in range(n):
        for j in range(i + 1, n):
            dx, dy = x[i] - x[j], y[i] - y[j]
            if dx == 0 and dy == 0:
                continue
            if dx == 0:
                tie_x += 1
            elif dy == 0:
                tie_y += 1
            elif (dx > 0) == (dy > 0):
                concordant += 1
            else:
                discordant += 1
    denom = ((concordant + discordant + tie_x) * (concordant + discordant + tie_y)) ** 0.5
    return (concordant - discordant) / denom if denom else 0.0


def top_k_overlap(score_a: dict, score_b: dict, k: int = 3) -> float:
    """Fraction of the top-k items shared between two scorings."""
    def top(s):
        return {n for n, _ in sorted(s.items(), key=lambda kv: -kv[1])[:k]}
    return len(top(score_a) & top(score_b)) / k


# --------------------------------------------------------------------------- #
# Methods under comparison — each maps asset name -> priority score (higher = worse)
# --------------------------------------------------------------------------- #
def _drop(weights: dict, key: str) -> dict:
    kept = {k: v for k, v in weights.items() if k != key}
    total = sum(kept.values())
    return {k: v / total for k, v in kept.items()}


def _model_scores(arch, graph, cves, lw=None, iw=None) -> dict:
    """The model's own ranking signal: severity (primary) with impact as tiebreak —
    exactly the order score_architecture/_rank produces."""
    s = score_architecture(arch, graph, cves, likelihood_weights=lw, impact_weights=iw)
    return {n: v["severity"] * 1000 + v["impact"] for n, v in s.items()}


def _entry_distance_scores(arch, reach) -> dict:
    import networkx as nx
    out = {}
    for name in arch.assets:
        dists = [nx.shortest_path_length(reach, e, name)
                 for e in arch.entry_nodes
                 if e in reach and name in reach and nx.has_path(reach, e, name)]
        out[name] = 1.0 / (1 + min(dists)) if dists else 0.0  # closer to entry = higher
    return out


def _cve_scores(arch, cves_by_asset) -> dict:
    out = {}
    for name in arch.assets:
        cves = cves_by_asset.get(name, [])
        if any(c.get("known_exploited") for c in cves):
            out[name] = 11.0  # KEV outranks any CVSS
        else:
            out[name] = max((c.get("cvss") or 0 for c in cves), default=0.0)
    return out


def methods_for(arch_path: str):
    arch = load_architecture(arch_path)
    graph = arch.graph()
    reach = arch.reachability_graph()
    snapshot = load_cve_snapshot()
    cves = {n: snapshot.get(a.cpe_hint() or "", []) for n, a in arch.assets.items()}

    model = _model_scores(arch, graph, cves)

    def ablate_lik(factor):
        return _model_scores(arch, graph, cves, lw=_drop(LIKELIHOOD_WEIGHTS, factor))

    methods = {
        "MODEL (full)": model,
        "BASE: criticality only": {n: CRITICALITY_BY_LEVEL.get(a.level.name, 50)
                                   for n, a in arch.assets.items()},
        "ablate exposure": ablate_lik("exposure"),
        "ablate auth": ablate_lik("auth"),
        "ablate blast-radius": _model_scores(arch, graph, cves,
                                             iw=_drop(IMPACT_WEIGHTS, "blast_radius")),
        "PROXY: betweenness": chokepoints(reach),
        "PROXY: entry distance": _entry_distance_scores(arch, reach),
        "PROXY: CVE severity": _cve_scores(arch, cves),
    }
    return arch, reach, cves, model, methods


_ABLATIONS = ["ablate exposure", "ablate auth", "ablate blast-radius"]
_PROXIES = ["PROXY: betweenness", "PROXY: entry distance", "PROXY: CVE severity"]


def run() -> str:
    lines = ["# Validity Experiment — Results\n",
             "_Generated by `python -m experiments.validity`. Metric: Kendall's tau-b vs the "
             "full model's ranking (1 = identical order, 0 = independent), with top-3 overlap._\n",
             "**Scope.** Tests discriminant validity (vs a trivial baseline), factor ablations, "
             "and convergence with independent lenses. It does NOT establish criterion validity — "
             "agreement with real expert judgement or incident outcomes — which needs human raters "
             "or labelled incidents.\n"]
    collected = {}

    for title, path in ARCHES.items():
        arch, reach, cves, model, methods = methods_for(path)
        names = list(arch.assets)
        mv = [model[n] for n in names]
        taus = {label: kendall_tau_b(mv, [s[n] for n in names])
                for label, s in methods.items() if label != "MODEL (full)"}

        lines.append(f"## {title}\n")
        lines.append("| method | tau-b vs model | top-3 overlap |")
        lines.append("|--------|---------------:|--------------:|")
        for label in methods:
            if label == "MODEL (full)":
                continue
            overlap = top_k_overlap(model, methods[label], 3) * 100
            lines.append(f"| {label} | {taus[label]:+.2f} | {overlap:.0f}% |")
        lines.append("")

        ranked = sorted(model.items(), key=lambda kv: -kv[1])
        scores_full = score_architecture(arch, arch.graph(), cves)
        paths = path_findings(reach, arch.entry_nodes, arch.target_nodes, scores_full)
        easiest = " -> ".join(paths[0]["path"]) if paths else "(none)"
        targets = ", ".join(arch.target_nodes)
        lines.append(f"- Top-ranked asset: **{ranked[0][0]}** (targets: {targets})")
        lines.append(f"- Easiest external->critical path: `{easiest}`\n")
        collected[title] = {"taus": taus, "top": ranked[0][0], "targets": arch.target_nodes}

    # ---- auto-derived findings (data-driven, so RESULTS stays reproducible) ----
    lines.append("## What the numbers say\n")
    for title, d in collected.items():
        taus = d["taus"]
        crit = taus["BASE: criticality only"]
        most = min(_ABLATIONS, key=lambda a: taus[a])      # lowest tau = removing it changes most
        least = max(_ABLATIONS, key=lambda a: taus[a])     # highest tau = most inert factor
        best_proxy = max(_PROXIES, key=lambda p: taus[p])
        face = "✓" if d["top"] in d["targets"] else "✗"
        lines.append(f"**{title}.**")
        lines.append(f"- *Discriminant:* the ranking tracks the trivial **criticality-only** "
                     f"baseline at tau-b {crit:+.2f} — the Purdue-level criticality table drives "
                     f"most of the order; the rest of the model refines the margins.")
        lines.append(f"- *Most influential factor:* **{most.replace('ablate ', '')}** "
                     f"(removing it drops tau-b to {taus[most]:+.2f}). "
                     f"*Most inert:* **{least.replace('ablate ', '')}** ({taus[least]:+.2f} — "
                     f"removing it barely changes the ranking).")
        proxy_name = best_proxy.replace('PROXY: ', '')
        lines.append(f"- *Convergent:* weak — the closest independent lens ({proxy_name}) only "
                     f"reaches tau-b {taus[best_proxy]:+.2f}; the model does not reduce to any "
                     f"single lens (and anti-correlates with raw entry-distance, since impact "
                     f"outweighs exposure).")
        lines.append(f"- *Face validity:* top-ranked asset is a declared target — {face}.\n")

    lines.append("## Honest reading\n")
    lines.append("- The headline output (*which assets to harden first*) is largely determined by "
                 "process criticality (Purdue level). The likelihood factors and CVE signal refine "
                 "the ordering but rarely change the top of the list.")
    lines.append("- The **known-exploited / CVE signal** is now applied as a band escalator, not "
                 "a weighted likelihood factor — an ablation (ablation_followup.py) showed it "
                 "changed no band or rank as a weight, so KEV CVEs now escalate the band directly.")
    lines.append("- There is **no independent corroboration** that the combined ranking is right; "
                 "convergent agreement with structural and vulnerability lenses is weak by design.")
    lines.append("- Architectures are **n=2, synthetic, single-author**, so face validity is weak. "
                 "Criterion validity (vs expert raters or real incidents) remains untested.\n")

    Path("experiments/RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
    return "\n".join(lines)


if __name__ == "__main__":
    print(run())
