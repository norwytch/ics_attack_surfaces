"""Asset -> ATT&CK technique mapping (data-driven) + CVE attachment.

A data-driven rule engine (`rule_matches`, `map_asset_to_techniques`) maps asset
attributes to ATT&CK for ICS techniques; CVE attachment is delegated to `data_sources`.
"""
from __future__ import annotations

import dataclasses

import yaml

from .assets import Asset

_ASSET_FIELDS = {f.name for f in dataclasses.fields(Asset)}


def load_rules(path: str) -> list[dict]:
    """Load and validate mapping rules from YAML.

    Each rule's `when` keys must name real Asset fields — a typo (e.g. `protocol`
    for `protocols`) would otherwise match nothing silently and drop coverage.
    """
    with open(path, encoding="utf-8") as f:
        rules = yaml.safe_load(f).get("rules", [])
    for rule in rules:
        unknown = set(rule.get("when", {})) - _ASSET_FIELDS
        if unknown:
            raise ValueError(
                f"Rule {rule.get('id', '?')!r}: `when` references unknown "
                f"asset field(s) {sorted(unknown)}; valid fields: {sorted(_ASSET_FIELDS)}"
            )
    return rules


def rule_matches(asset: Asset, when: dict) -> bool:
    """AND-of-fields match.

    For a `when` field whose value is a list, the rule matches if ANY listed value is
    present in the asset's corresponding list attribute. For a scalar value, it matches
    on equality against the asset's attribute.
    """
    for field_name, expected in when.items():
        actual = getattr(asset, field_name, None)
        if isinstance(expected, list):
            actual_set = set(actual) if isinstance(actual, list) else {actual}
            if not actual_set.intersection(expected):
                return False
        else:
            if actual != expected:
                return False
    return True


def validate_rules_against_attack(rules: list[dict], attack: dict) -> dict[str, list]:
    """Return {rule_id: [stale technique IDs]} for IDs not current in `attack`.

    Catches revoked/renamed/typo'd technique references (e.g. T0855, revoked in favor
    of T1692.001) before they silently become id-only entries in the briefing.
    """
    known = set(attack)
    stale = {}
    for rule in rules:
        bad = [t for t in rule.get("techniques", []) if t not in known]
        if bad:
            stale[rule.get("id", "?")] = bad
    return stale


def resolve_techniques(ids, attack: dict | None) -> list[dict]:
    """Turn technique IDs into {id, name, url} using parsed ATT&CK data.

    Unknown IDs (or no ATT&CK data) degrade gracefully to id-only entries, so the
    briefing never crashes on a rule referencing a technique not in the bundle.
    """
    attack = attack or {}
    out = []
    for tid in ids:
        meta = attack.get(tid, {})
        out.append({"id": tid, "name": meta.get("name", ""), "url": meta.get("url")})
    return out


def map_asset_to_techniques(asset: Asset, rules: list[dict], *,
                            kev: set | None = None, fetch_cves: bool = False):
    """Return (matched_rules, cves) for an asset.

    matched_rules carry their technique IDs and rationale straight into the briefing.
    CVEs are fetched (and KEV-flagged) only when fetch_cves is True — the network
    call is opt-in so the core mapping stays offline and fast.
    """
    matched = [r for r in rules if rule_matches(asset, r.get("when", {}))]
    cves = []
    if fetch_cves:
        from .data_sources import lookup_cves_by_cpe

        cves = lookup_cves_by_cpe(asset.cpe_hint(), kev=kev)
    return matched, cves


def map_architecture(architecture, rules: list[dict], *, attack: dict | None = None,
                     kev: set | None = None, fetch_cves: bool = False) -> dict:
    """Map every asset. Returns name -> {rules, techniques, cves}.

    `techniques` is a sorted list of {id, name, url} (names filled in when `attack`
    data is supplied). Pass fetch_cves=True (with an optional `kev` set) to enrich.
    """
    out = {}
    for name, asset in architecture.assets.items():
        matched, cves = map_asset_to_techniques(
            asset, rules, kev=kev, fetch_cves=fetch_cves
        )
        ids = sorted({t for r in matched for t in r.get("techniques", [])})
        out[name] = {
            "rules": matched,
            "techniques": resolve_techniques(ids, attack),
            "cves": cves,
        }
    return out
