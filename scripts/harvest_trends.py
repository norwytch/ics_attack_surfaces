"""Harvest MITRE-curated technique lists + citations for ICS campaigns.

Reads the ATT&CK for ICS STIX bundle and, for each target software object
(by ATT&CK ID, e.g. S0603 Stuxnet), extracts the techniques it `uses` and the
external references (citations) MITRE attaches to it.

Filters out deprecated/revoked legacy duplicates and drops `uses` relationships
that point at revoked/deprecated techniques, so only current technique IDs remain.

Usage: python -m scripts.harvest_trends   (prints a YAML-ish draft to stdout)
"""
from __future__ import annotations

import json
from pathlib import Path

BUNDLE = "data/attack_ics.json"
TARGETS = {  # ATT&CK software ID -> display name (curate the result by hand after)
    "S0603": "Stuxnet",
    "S1009": "Triton / TRISIS",
    "S0604": "Industroyer / CrashOverride",
}


def _mitre_id(obj):
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return None


def _is_current(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def harvest(bundle_path=BUNDLE):
    objs = json.loads(Path(bundle_path).read_text(encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objs}

    # current malware objects keyed by ATT&CK ID (drops deprecated legacy duplicates)
    software = {}
    for o in objs:
        if o.get("type") == "malware" and _is_current(o):
            mid = _mitre_id(o)
            if mid:
                software[mid] = o

    out = {}
    for sid, label in TARGETS.items():
        obj = software.get(sid)
        if not obj:
            out[sid] = {"label": label, "error": "not found"}
            continue
        techniques = []
        for rel in objs:
            if (rel.get("type") == "relationship"
                    and rel.get("relationship_type") == "uses"
                    and rel.get("source_ref") == obj["id"]):
                target = by_id.get(rel.get("target_ref"), {})
                if target.get("type") == "attack-pattern" and _is_current(target):
                    tid = _mitre_id(target)
                    if tid:
                        techniques.append((tid, target.get("name", "")))
        citations = [
            {"source": r.get("source_name"), "url": r.get("url")}
            for r in obj.get("external_references", [])
            if r.get("source_name") != "mitre-attack" and r.get("url")
        ]
        out[sid] = {
            "label": label,
            "attack_id": sid,
            "techniques": sorted(set(techniques)),
            "citations": citations,
        }
    return out


def main():
    for sid, data in harvest().items():
        print(f"\n=== {data.get('label')} ({sid}) ===")
        if data.get("error"):
            print("  ", data["error"])
            continue
        print(f"  techniques ({len(data['techniques'])}):")
        for tid, name in data["techniques"]:
            print(f"    {tid:12} {name}")
        print(f"  citations ({len(data['citations'])}):")
        for c in data["citations"]:
            print(f"    {c['source']}\n      {c['url']}")


if __name__ == "__main__":
    main()
