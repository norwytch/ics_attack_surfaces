"""Risk scoring (NIST SP 800-30) and segmentation-aware attack-path analysis.

Likelihood and impact are scored 0-100 and combined into a risk band via the 800-30
Table I-2 lookup (see data/risk_rubric.md). Attack paths and chokepoints run on the
policy-respecting reachability graph; `sensitivity()` stress-tests the weight choices.
"""
from __future__ import annotations

import warnings
from itertools import islice

BAND_ORDER = ["Very Low", "Low", "Moderate", "High", "Very High"]
_BAND_BOUNDS = (20, 40, 60, 80)  # upper-exclusive cutoffs between the five bands


def _band_index(score: float) -> int:
    """0-100 score -> band ordinal 0 (Very Low) .. 4 (Very High)."""
    idx = 0
    for bound in _BAND_BOUNDS:
        if score < bound:
            return idx
        idx += 1
    return idx  # 4 = Very High


def band(score: float) -> str:
    """Map a 0-100 score to its qualitative band label."""
    return BAND_ORDER[_band_index(score)]


# NIST SP 800-30 Rev. 1, Table I-2 — Level of Risk as a function of Likelihood
# (row) and Impact (column), each Very Low(0)..Very High(4). Cells are risk-band
# ordinals into BAND_ORDER. This lookup is authoritative for the reported risk
# band (it does not deflate the way a normalized Likelihood*Impact product does).
RISK_MATRIX = [
    [0, 0, 0, 1, 1],  # Very Low likelihood
    [0, 1, 1, 1, 2],  # Low
    [0, 1, 2, 2, 3],  # Moderate
    [0, 1, 2, 3, 4],  # High
    [0, 1, 2, 3, 4],  # Very High
]


def risk_severity(likelihood: float, impact: float) -> int:
    """Risk-band ordinal (0-4) via the 800-30 Table I-2 lookup."""
    return RISK_MATRIX[_band_index(likelihood)][_band_index(impact)]


def risk_band(likelihood: float, impact: float) -> str:
    """Risk band label via the 800-30 Table I-2 lookup (authoritative)."""
    return BAND_ORDER[risk_severity(likelihood, impact)]


IT_ZONES = {"L4_ENTERPRISE", "L5_INTERNET"}
OT_ZONES = {"L0_PROCESS", "L1_CONTROL", "L2_SUPERVISORY"}


def attack_paths(graph, entry_nodes, target_nodes, k: int = 5, weight: str | None = "weight"):
    """k easiest paths from each entry node to each target.

    Runs on whatever graph is passed — give it `architecture.reachability_graph()` so
    edges the segmentation policy denies are absent. With `weight` set, paths are ranked
    by summed hop difficulty (easiest first); missing edge weights default to 1.
    """
    import networkx as nx

    missing = [n for n in set(entry_nodes) | set(target_nodes) if n not in graph]
    if missing:
        warnings.warn(f"attack_paths: nodes not in graph, skipped: {sorted(missing)}",
                      stacklevel=2)
    paths: list = []
    for entry in entry_nodes:
        for target in target_nodes:
            if entry == target or entry not in graph or target not in graph:
                continue
            try:
                paths.extend(islice(
                    nx.shortest_simple_paths(graph, entry, target, weight=weight), k))
            except nx.NetworkXNoPath:
                continue
    return paths


def _path_cost(graph, path) -> float:
    return sum(graph[u][v].get("weight", 1.0) for u, v in zip(path, path[1:], strict=False))


def segmentation_violations(architecture) -> list[dict]:
    """Physical connections the policy permits that cross the IT/OT boundary directly.

    A permitted edge from an enterprise/internet asset straight into an OT zone skips
    the DMZ — the segmentation control that should mediate it. These are the
    architecture's most dangerous allowances (e.g. the Oldsmar remote-access pattern).
    """
    policy = architecture.segmentation
    seen, out = set(), []
    for a in architecture.assets.values():
        for other in a.connections:
            b = architecture.assets[other]
            key = frozenset({a.name, b.name})
            if key in seen:
                continue
            za, zb = a.level.name, b.level.name
            crosses = (za in IT_ZONES and zb in OT_ZONES) or (zb in IT_ZONES and za in OT_ZONES)
            if crosses and (policy.permits(a, b) or policy.permits(b, a)):
                seen.add(key)
                out.append({"from": a.name, "to": b.name, "from_zone": za, "to_zone": zb})
    return out


def chokepoints(graph) -> dict:
    """Betweenness centrality — assets most often on critical paths."""
    import networkx as nx

    return nx.betweenness_centrality(graph)


# Factor weights (sum to 1.0 within each dimension) and the per-Purdue-level
# process-criticality scale. Keep in sync with data/risk_rubric.md.
#
# Note: a former third likelihood factor (known-exploited / CVSS) was removed after an
# ablation (experiments/ablation_followup.py) showed it changed no asset's band or rank,
# even for the asset that carried a KEV CVE. The actively-exploited signal is now applied
# as a band escalator in score_architecture (see KEV escalator), where it is decision-
# relevant, rather than as a weighted input that washed out.
LIKELIHOOD_WEIGHTS = {"exposure": 0.6, "auth": 0.4}
IMPACT_WEIGHTS = {"criticality": 0.6, "blast_radius": 0.4}
CRITICALITY_BY_LEVEL = {
    "L0_PROCESS": 100, "L1_CONTROL": 100, "L2_SUPERVISORY": 60,
    "L3_OPERATIONS": 40, "L3_5_DMZ": 30, "L4_ENTERPRISE": 20, "L5_INTERNET": 10,
}
_EXPOSURE_DECAY = 0.7  # exposure = 100 * decay**(hops from nearest entry)


def _exposure(graph, entry_nodes, name) -> float:
    """100 at an entry node, decaying with shortest-path distance; 0 if unreachable."""
    import networkx as nx

    dists = [
        nx.shortest_path_length(graph, e, name)
        for e in entry_nodes
        if e in graph and name in graph and nx.has_path(graph, e, name)
    ]
    return 100.0 * (_EXPOSURE_DECAY ** min(dists)) if dists else 0.0


def _has_kev(cves) -> bool:
    """True if any attached CVE is in the CISA KEV catalog (actively exploited)."""
    return any(c.get("known_exploited") for c in (cves or []))


def _downstream(graph, name) -> set:
    """Assets below `name` in the Purdue stack reachable by descending edges.

    An edge is 'downstream' only toward a strictly lower Purdue level (toward the
    physical process), so blast radius measures what a compromise threatens below it.
    """
    def level(n):
        return graph.nodes[n]["asset"].level.value

    seen, stack = set(), [name]
    while stack:
        cur = stack.pop()
        for nb in graph.neighbors(cur):
            if nb not in seen and level(nb) < level(cur):
                seen.add(nb)
                stack.append(nb)
    return seen


def score_likelihood(asset, graph, entry_nodes, weights=None) -> float:
    """0-100 likelihood per the 800-30 rubric (exposure, protocol authentication)."""
    weights = weights or LIKELIHOOD_WEIGHTS
    factors = {
        "exposure": _exposure(graph, entry_nodes, asset.name),
        "auth": 100.0 if not asset.authenticated else 20.0,
    }
    return round(sum(factors[k] * weights[k] for k in weights), 1)


def score_impact(asset, graph, weights=None) -> float:
    """0-100 impact per the 800-30 rubric (process criticality, blast radius)."""
    weights = weights or IMPACT_WEIGHTS
    n = graph.number_of_nodes()
    factors = {
        "criticality": float(CRITICALITY_BY_LEVEL.get(asset.level.name, 50)),
        "blast_radius": 100.0 * len(_downstream(graph, asset.name)) / (n - 1) if n > 1 else 0.0,
    }
    return round(sum(factors[k] * weights[k] for k in weights), 1)


def score_architecture(architecture, graph=None, cves_by_asset=None,
                       likelihood_weights=None, impact_weights=None,
                       kev_escalate=True) -> dict:
    """Per-asset {likelihood, impact, band, severity, kev_escalated} — the report's input.

    The risk band comes from the NIST 800-30 Table I-2 lookup, then a **KEV escalator**:
    an asset carrying an actively-exploited (CISA KEV) CVE has its band bumped up one level
    (capped at Very High), reflecting CISA BOD 22-01's must-patch posture. Weights are
    injectable so `sensitivity()` can perturb them; `kev_escalate=False` disables the bump.
    """
    graph = graph if graph is not None else architecture.graph()
    cves_by_asset = cves_by_asset or {}
    out = {}
    for name, asset in architecture.assets.items():
        likelihood = score_likelihood(asset, graph, architecture.entry_nodes,
                                      weights=likelihood_weights)
        impact = score_impact(asset, graph, weights=impact_weights)
        severity = risk_severity(likelihood, impact)
        escalated = kev_escalate and _has_kev(cves_by_asset.get(name))
        if escalated:
            severity = min(4, severity + 1)
        out[name] = {
            "likelihood": likelihood,
            "impact": impact,
            "band": BAND_ORDER[severity],
            "severity": severity,
            "kev_escalated": escalated,
        }
    return out


def _rank(scores) -> list:
    """Asset names ordered by risk severity (then impact) — highest first."""
    return [n for n, _ in sorted(scores.items(),
                                 key=lambda kv: (-kv[1]["severity"], -kv[1]["impact"]))]


def _perturbed_weights(base: dict, perturb: float) -> list:
    """Every weight vector that scales each weight by (1-perturb), 1, or (1+perturb),
    renormalized to sum to 1."""
    from itertools import product

    keys = list(base)
    out = []
    for combo in product((1 - perturb, 1.0, 1 + perturb), repeat=len(keys)):
        scaled = {k: base[k] * f for k, f in zip(keys, combo, strict=True)}
        total = sum(scaled.values())
        out.append({k: v / total for k, v in scaled.items()})
    return out


def sensitivity(architecture, graph=None, cves_by_asset=None,
                perturb: float = 0.2, top_n: int = 3) -> dict:
    """Does the risk ranking depend on the exact factor weights?

    Re-scores the architecture under every combination of likelihood and impact
    weights perturbed by +/-`perturb`, and reports how stable the top-N priority set
    and per-asset bands are. A high stability fraction means the conclusions are robust
    to the weights, not an artifact of the specific numbers chosen.
    """
    graph = graph if graph is not None else architecture.graph()
    base = score_architecture(architecture, graph, cves_by_asset)
    base_rank = _rank(base)
    base_top, base_first = set(base_rank[:top_n]), base_rank[0]

    runs = top_stable = top1_stable = band_match = band_total = 0
    contenders = set()
    for lw in _perturbed_weights(LIKELIHOOD_WEIGHTS, perturb):
        for iw in _perturbed_weights(IMPACT_WEIGHTS, perturb):
            s = score_architecture(architecture, graph, cves_by_asset,
                                   likelihood_weights=lw, impact_weights=iw)
            r = _rank(s)
            top_stable += set(r[:top_n]) == base_top
            top1_stable += r[0] == base_first
            contenders |= set(r[:top_n])
            for name in s:
                band_total += 1
                band_match += s[name]["band"] == base[name]["band"]
            runs += 1

    return {
        "perturbations": runs,
        "perturb": perturb,
        "top_n": top_n,
        "baseline_top_n": base_rank[:top_n],
        "top1_stable_fraction": round(top1_stable / runs, 3),
        "top_n_set_stable_fraction": round(top_stable / runs, 3),
        "top_n_contenders": sorted(contenders),
        "band_stable_fraction": round(band_match / band_total, 3),
    }


def path_findings(graph, entry_nodes, target_nodes, scores=None, k=5) -> list[dict]:
    """Rank attack paths for the briefing: shortest first, then highest target risk."""
    scores = scores or {}
    findings = [
        {
            "path": path,
            "length": len(path) - 1,  # edges traversed
            "cost": round(_path_cost(graph, path), 1),  # summed hop difficulty
            "target": path[-1],
            "target_band": scores.get(path[-1], {}).get("band"),
            "target_severity": scores.get(path[-1], {}).get("severity"),
        }
        for path in attack_paths(graph, entry_nodes, target_nodes, k=k)
    ]
    findings.sort(key=lambda f: (f["cost"], f["length"], -(f["target_severity"] or 0)))
    return findings
