"""End-to-end pipeline: load → map → score → paths → trends → briefing + figures.

Runs fully offline by default. Pass --cves to enrich with live NVD/CISA-KEV data
(network + slower). Regenerates results/briefing.md and results/figures/*.png.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .assets import load_architecture
from .frameworks import write_navigator_layer
from .mapping import load_rules, map_architecture
from .report import (
    generate_briefing,
    plot_exposure_heatmap,
    plot_network,
    plot_risk_matrix,
)
from .scoring import (
    chokepoints,
    path_findings,
    score_architecture,
    segmentation_violations,
)
from .trends import load_campaigns, map_campaigns_to_exposure


def build(arch_path="data/reference_architecture.yaml",
          rules_path="data/mapping_rules.yaml",
          attack_path="data/attack_ics.json",
          trends_path="data/threat_trends.yaml",
          out_dir="results",
          fetch_cves=False) -> str:
    """Run the full pipeline. Returns the path to the generated briefing."""
    arch = load_architecture(arch_path)
    rules = load_rules(rules_path)

    # ATT&CK data is optional (gitignored download); names degrade gracefully without it.
    from .data_sources import load_cve_snapshot

    attack = None
    if Path(attack_path).exists():
        from .data_sources import load_attack_ics
        attack = load_attack_ics(attack_path)
    elif fetch_cves:  # if we're already going online, grab it too
        from .data_sources import fetch_attack_ics, load_attack_ics
        attack = load_attack_ics(fetch_attack_ics(attack_path))

    kev = None
    if fetch_cves:
        from .data_sources import fetch_kev_catalog
        kev = fetch_kev_catalog()

    mapped = map_architecture(arch, rules, attack=attack, kev=kev, fetch_cves=fetch_cves)
    if not fetch_cves:
        # offline default: attach CVEs from the committed snapshot so the briefing shows
        # real CVEs + KEV flags without a live NVD call (run `--cves` to refresh live)
        snapshot = load_cve_snapshot()
        for name, asset in arch.assets.items():
            mapped[name]["cves"] = snapshot.get(asset.cpe_hint() or "", [])
    graph = arch.graph()                     # physical topology: diagram + blast-radius impact
    reach = arch.reachability_graph()        # policy-respecting: attack paths + chokepoints
    cves_by_asset = {n: m["cves"] for n, m in mapped.items()}
    scores = score_architecture(arch, graph, cves_by_asset)
    paths = path_findings(reach, arch.entry_nodes, arch.target_nodes, scores)
    chokes = chokepoints(reach)
    violations = segmentation_violations(arch)
    campaigns = map_campaigns_to_exposure(mapped, load_campaigns(trends_path))

    figdir = f"{out_dir}/figures"
    plot_network(graph, scores, f"{figdir}/network.png")
    plot_exposure_heatmap(mapped, f"{figdir}/heatmap.png")
    plot_risk_matrix(scores, f"{figdir}/risk_matrix.png")
    write_navigator_layer(arch, mapped, f"{out_dir}/attack_navigator_layer.json")

    return generate_briefing(arch, mapped, scores, paths, chokes, campaigns, violations,
                             f"{out_dir}/briefing.md")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Generate the ICS vulnerability briefing.")
    ap.add_argument("--arch", default="data/reference_architecture.yaml",
                    help="reference architecture YAML to analyze")
    ap.add_argument("--rules", default="data/mapping_rules.yaml",
                    help="asset->technique mapping rules YAML")
    ap.add_argument("--trends", default="data/threat_trends.yaml",
                    help="curated threat-trend campaign YAML")
    ap.add_argument("--cves", action="store_true",
                    help="enrich with live NVD CVEs + CISA KEV (network, slower)")
    ap.add_argument("--out", default="results", help="output directory")
    args = ap.parse_args(argv)
    dest = build(arch_path=args.arch, rules_path=args.rules, trends_path=args.trends,
                 out_dir=args.out, fetch_cves=args.cves)
    print(f"Briefing written to {dest}")
    print(f"Figures written to {args.out}/figures/")


if __name__ == "__main__":
    main()
