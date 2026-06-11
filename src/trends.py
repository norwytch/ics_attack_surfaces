"""Threat-trend mapping.

Connects the modeled architecture's technique exposure to real, cited public ICS
campaigns (data/threat_trends.yaml). Loader is functional; correlation is stubbed.
"""
from __future__ import annotations

import yaml


def load_campaigns(path: str = "data/threat_trends.yaml") -> list[dict]:
    """Load curated, cited campaign references."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f).get("campaigns", [])


def map_campaigns_to_exposure(exposure: dict, campaigns: list[dict]) -> list[dict]:
    """For each campaign, find which modeled assets share its techniques.

    `exposure` is the output of mapping.map_architecture (name -> {techniques, ...}).
    Returns campaigns annotated with `matches` (per-asset shared technique IDs) and
    `matched_techniques` (the union), sorted by number of assets hit (most first).
    """
    out = []
    for campaign in campaigns:
        campaign_techs = set(campaign.get("techniques", []))
        matches = []
        for name, data in exposure.items():
            asset_techs = {t["id"] for t in data.get("techniques", [])}
            shared = sorted(campaign_techs & asset_techs)
            if shared:
                matches.append({"asset": name, "techniques": shared})
        out.append({
            **campaign,
            "matches": matches,
            "matched_techniques": sorted({t for m in matches for t in m["techniques"]}),
        })
    out.sort(key=lambda c: len(c["matches"]), reverse=True)
    return out
