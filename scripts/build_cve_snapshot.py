"""Build the committed CVE snapshot used for offline briefings.

For every distinct product across the reference architectures, resolves its CPE and
queries NVD for the worst CVEs (flagged against CISA KEV), then writes
data/cve_snapshot.json keyed by the asset cpe_hint. The pipeline loads this by default
so the briefing shows real CVEs without a live call; `--cves` refreshes live.

Run manually to refresh:  python -m scripts.build_cve_snapshot
(NVD is rate-limited without an API key — set NVD_API_KEY to speed it up.)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ics_modeler.assets import load_architecture
from ics_modeler.data_sources import fetch_kev_catalog, lookup_cves_by_cpe

ARCHES = ["data/reference_architecture.yaml", "data/water_treatment.yaml"]
DEST = "data/cve_snapshot.json"


def main():
    kev = fetch_kev_catalog()
    kev_meta = json.loads(Path("data/cache/kev.json").read_text(encoding="utf-8"))
    print(f"KEV catalog: {len(kev)} CVE IDs")
    products, seen = {}, set()
    for path in ARCHES:
        for asset in load_architecture(path).assets.values():
            hint = asset.cpe_hint()
            if not hint or hint in seen:
                continue
            seen.add(hint)
            cves = lookup_cves_by_cpe(hint, kev=kev)
            products[hint] = cves
            kev_n = sum(c["known_exploited"] for c in cves)
            print(f"  {hint:48} {len(cves):2} CVEs  ({kev_n} in KEV)")
    snapshot = {
        "_meta": {
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "kev_catalog_version": kev_meta.get("catalogVersion", "?"),
            "kev_date_released": kev_meta.get("dateReleased", "?"),
            "kev_count": len(kev),
            "nvd_api": "2.0",
        },
        "products": products,
    }
    Path(DEST).write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    print(f"Wrote {DEST} ({len(products)} products)")


if __name__ == "__main__":
    main()
