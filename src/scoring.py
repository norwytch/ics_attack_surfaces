"""Likelihood/impact scoring (NIST SP 800-30) + attack-path / chokepoint analysis.

Attack-path functions are functional. Likelihood/impact scoring is stubbed — implement
per data/risk_rubric.md (0-100 internal, qualitative bands in the briefing).
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
    paths = []
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
    return sum(graph[u][v].get("weight", 1.0) for u, v in zip(path, path[1:]))


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
LIKELIHOOD_WEIGHTS = {"exposure": 0.4, "auth": 0.3, "known_exploited": 0.3}
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


def _vuln_factor(cves) -> float:
    """100 if any attached CVE is in CISA KEV, else scaled by the worst CVSS, else 0."""
    if not cves:
        return 0.0
    if any(c.get("known_exploited") for c in cves):
        return 100.0
    scores = [c["cvss"] for c in cves if c.get("cvss") is not None]
    return min(100.0, max(scores) * 10) if scores else 0.0


def _downstream(graph, name) -> set:
    """Assets below `name` in the Purdue stack reachable by descending edges.

    An edge is 'downstream' only toward a strictly lower Purdue level (toward the
    physical process), so blast radius measures what a compromise threatens below it.
    """
    level = lambda n: graph.nodes[n]["asset"].level.value
    seen, stack = set(), [name]
    while stack:
        cur = stack.pop()
        for nb in graph.neighbors(cur):
            if nb not in seen and level(nb) < level(cur):
                seen.add(nb)
                stack.append(nb)
    return seen


def score_likelihood(asset, graph, entry_nodes, cves=None) -> float:
    """0-100 likelihood per the 800-30 rubric (exposure, auth, known-exploited)."""
    factors = {
        "exposure": _exposure(graph, entry_nodes, asset.name),
        "auth": 100.0 if not asset.authenticated else 20.0,
        "known_exploited": _vuln_factor(cves),
    }
    return round(sum(factors[k] * w for k, w in LIKELIHOOD_WEIGHTS.items()), 1)


def score_impact(asset, graph) -> float:
    """0-100 impact per the 800-30 rubric (process criticality, blast radius)."""
    n = graph.number_of_nodes()
    factors = {
        "criticality": float(CRITICALITY_BY_LEVEL.get(asset.level.name, 50)),
        "blast_radius": 100.0 * len(_downstream(graph, asset.name)) / (n - 1) if n > 1 else 0.0,
    }
    return round(sum(factors[k] * w for k, w in IMPACT_WEIGHTS.items()), 1)


def score_architecture(architecture, graph=None, cves_by_asset=None) -> dict:
    """Per-asset {likelihood, impact, band, severity} — the report's scoring input.

    The risk band comes from the NIST 800-30 Table I-2 lookup (risk_band); severity
    is its 0-4 ordinal, used for ranking. Likelihood and impact remain the 0-100 axes
    for the risk-matrix scatter.
    """
    graph = graph if graph is not None else architecture.graph()
    cves_by_asset = cves_by_asset or {}
    out = {}
    for name, asset in architecture.assets.items():
        likelihood = score_likelihood(
            asset, graph, architecture.entry_nodes, cves_by_asset.get(name)
        )
        impact = score_impact(asset, graph)
        severity = risk_severity(likelihood, impact)
        out[name] = {
            "likelihood": likelihood,
            "impact": impact,
            "band": BAND_ORDER[severity],
            "severity": severity,
        }
    return out


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
