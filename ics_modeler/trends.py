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


_CONFIDENCE_BANDS = [(0.6, "High"), (0.4, "Moderate"), (0.0, "Low")]


def _confidence(coverage: float) -> str:
    """Map technique-coverage fraction to a confidence label."""
    for threshold, label in _CONFIDENCE_BANDS:
        if coverage >= threshold:
            return label
    return "Low"


def map_campaigns_to_exposure(exposure: dict, campaigns: list[dict]) -> list[dict]:
    """Correlate campaigns to the architecture, with a confidence score per campaign.

    A binary "shares >=1 technique" overstates the link — sharing one technique with
    Stuxnet does not make a plant Stuxnet-vulnerable. Instead each campaign gets a
    **coverage** = the fraction of its characteristic techniques this architecture
    exposes anywhere, and a derived **confidence** band. Per-asset matches carry their
    own `fraction` so weak single-technique overlaps are visibly demoted. `exposure` is
    the output of mapping.map_architecture. Sorted by coverage (strongest first).
    """
    all_exposed = {t["id"] for d in exposure.values() for t in d.get("techniques", [])}
    out = []
    for campaign in campaigns:
        campaign_techs = set(campaign.get("techniques", []))
        if not campaign_techs:
            continue
        matches = []
        for name, data in exposure.items():
            shared = sorted(campaign_techs & {t["id"] for t in data.get("techniques", [])})
            if shared:
                matches.append({"asset": name, "techniques": shared,
                                "fraction": round(len(shared) / len(campaign_techs), 2)})
        matches.sort(key=lambda m: -m["fraction"])
        covered = sorted(campaign_techs & all_exposed)
        coverage = round(len(covered) / len(campaign_techs), 2)
        out.append({
            **campaign,
            "matches": matches,
            "matched_techniques": covered,
            "coverage": coverage,
            "confidence": _confidence(coverage),
        })
    out.sort(key=lambda c: c["coverage"], reverse=True)
    return out
