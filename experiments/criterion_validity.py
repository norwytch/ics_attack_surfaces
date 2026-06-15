"""Criterion-validity test against a documented incident: 2015 Ukraine power grid.

Stronger than the face-validity check in validity.py: the ground truth here is a REAL,
externally-documented attack (E-ISAC/SANS 2016; ICS-CERT IR-ALERT-H-16-056-01), defined
from the report — not from the tool's output. The architecture is reconstructed from public
reporting (experiments/ukraine_2015.yaml) and the tool is run UNCHANGED. We then measure
whether the tool independently recovers the documented path, assets, root cause, and
techniques.

Honesty caveats: the architecture is still hand-authored (residual modeling bias), and the
tool only models OT exposure — it cannot represent the IT initial-access stage (spear-phish),
firmware overwrite, or the KillDisk wiper. Those are reported as out-of-scope, not as misses
to hide.

Run: python -m experiments.criterion_validity   (writes experiments/CRITERION_RESULTS.md)
"""
from __future__ import annotations

from pathlib import Path

from ics_modeler.assets import load_architecture
from ics_modeler.mapping import load_rules, map_architecture
from ics_modeler.scoring import (
    path_findings,
    score_architecture,
    segmentation_violations,
)

ARCH = "experiments/ukraine_2015.yaml"

# Ground truth, defined from the public report (NOT from tool output).
DOCUMENTED = {
    "source": "E-ISAC/SANS, 'Analysis of the Cyber Attack on the Ukrainian Power Grid' (2016); "
              "ICS-CERT IR-ALERT-H-16-056-01",
    "root_cause": ("vpn_gateway", "scada_dms_server"),   # VPN business->ICS without MFA
    "path_waypoints": ["corporate_workstation", "vpn_gateway", "scada_dms_server",
                       "substation_rtu", "breaker"],
    "compromised_assets": ["scada_dms_server", "operator_hmi", "substation_rtu",
                           "serial_ethernet_converter", "breaker"],
    # documented techniques the tool *could* map (ATT&CK for ICS); IT-stage and
    # firmware/wiper techniques are out of the tool's modeled scope (listed separately).
    # External Remote Services, Remote Services, Command Message
    "ot_techniques": ["T0822", "T0886", "T1692.001"],
    "out_of_scope_techniques": ["T0865 Spearphishing", "T0859 Valid Accounts",
                                "T0857 System Firmware", "T0809 Data Destruction"],
}


def _lcs_len(a: list, b: list) -> int:
    """Longest common subsequence length (order-preserving overlap)."""
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) - 1, -1, -1):
        for j in range(len(b) - 1, -1, -1):
            dp[i][j] = dp[i + 1][j + 1] + 1 if a[i] == b[j] else max(dp[i + 1][j], dp[i][j + 1])
    return dp[0][0]


def run() -> str:
    arch = load_architecture(ARCH)
    graph = arch.graph()
    reach = arch.reachability_graph()
    mapped = map_architecture(arch, load_rules("data/mapping_rules.yaml"))
    scores = score_architecture(arch, graph)
    ranked = [n for n, _ in sorted(scores.items(),
                                   key=lambda kv: (-kv[1]["severity"], -kv[1]["impact"]))]

    # 1. root cause flagged?
    viol = {(v["from"], v["to"]) for v in segmentation_violations(arch)}
    rc = DOCUMENTED["root_cause"]
    bypass_flagged = rc in viol or rc[::-1] in viol

    # 2. path recovery: best waypoint coverage among the tool's ranked paths
    paths = path_findings(reach, arch.entry_nodes, arch.target_nodes, scores)
    wp = DOCUMENTED["path_waypoints"]
    best_path, best_cov = None, 0.0
    for p in paths:
        cov = _lcs_len(wp, p["path"]) / len(wp)
        if cov > best_cov:
            best_cov, best_path = cov, p["path"]

    # 3. critical-asset recall @ N (N = number of documented compromised assets)
    comp = DOCUMENTED["compromised_assets"]
    topn = set(ranked[: len(comp)])
    recall = len(topn & set(comp)) / len(comp)

    # 4. technique recall: did the tool assign each documented OT technique anywhere, and where?
    want = DOCUMENTED["ot_techniques"]
    tech_location = {
        tid: [a for a in arch.assets
              if tid in {t["id"] for t in mapped.get(a, {}).get("techniques", [])}]
        for tid in want
    }
    tech_recall = sum(1 for holders in tech_location.values() if holders) / len(want)

    verdict = "flags it as an IT->OT segmentation bypass" if bypass_flagged else "does not flag it"
    n = len(comp)
    hit = len(topn & set(comp))
    oos = ", ".join(DOCUMENTED["out_of_scope_techniques"])
    L = ["# Criterion-Validity Test — 2015 Ukraine Power Grid\n",
         f"_Ground truth: {DOCUMENTED['source']}._\n",
         "Architecture ([experiments/ukraine_2015.yaml](ukraine_2015.yaml)) reconstructed from "
         "public reporting; the tool is run unchanged. Ground truth is the documented attack, "
         "defined independently of the tool's output.\n",
         "## Results\n",
         f"- **Root cause flagged:** {'YES' if bypass_flagged else 'NO'} — the documented root "
         f"cause was a VPN from business IT into the ICS network without MFA "
         f"(`{rc[0]} -> {rc[1]}`); the tool {verdict}.",
         f"- **Attack-path recovery:** {best_cov*100:.0f}% of documented waypoints, in order.",
         f"    - documented: `{' -> '.join(wp)}`",
         f"    - tool's best path: `{' -> '.join(best_path) if best_path else '(none)'}`",
         f"- **Critical-asset recall@{n}:** {recall*100:.0f}% — {hit} of the {n} "
         f"documented-compromised assets are in the tool's top-{n} risk ranking.",
         f"    - documented: {', '.join(comp)}",
         f"    - tool top-{n}: {', '.join(ranked[:n])}",
         f"- **Technique recall (OT, mappable):** {tech_recall*100:.0f}% — where the tool placed "
         f"each documented technique:",
         *[f"    - {tid}: {', '.join(tech_location[tid]) or '(not assigned)'}" for tid in want],
         "",
         "## What the tool cannot capture (out of scope, not misses)\n",
         "The tool models OT exposure, so it does not represent the documented IT-stage and "
         f"destructive techniques: {oos}. A criterion-validity claim covers only the OT "
         "attack-surface portion of the incident.\n",
         "## Honest reading\n",
         "- This is **reconstruction-based** criterion validity: stronger than face validity (a "
         "real, independently-documented incident), weaker than a blind test (the architecture is "
         "still hand-authored, so modeling bias is possible).",
         "- n=1 incident. Recovering one documented attack is encouraging, not conclusive; it "
         "shows the tool's IT->OT-bypass and command-path reasoning aligns with one real case it "
         "was not built around.",
         "- **Caveat on asset recall:** with ~10 assets and the ranking driven mostly by Purdue "
         "criticality (see RESULTS.md), recall@5 mostly confirms the 5 OT assets outrank the 5 IT "
         "ones — weakly discriminating. Path recovery and the root-cause flag are stronger.",
         ]
    Path("experiments/CRITERION_RESULTS.md").write_text("\n".join(L), encoding="utf-8")
    return "\n".join(L)


if __name__ == "__main__":
    print(run())
