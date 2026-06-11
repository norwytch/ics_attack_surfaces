"""CISA advisory / NVD CVE / CISA KEV / MITRE ATT&CK fetchers.

All network fetchers cache to disk and only re-fetch when the cache is missing or
`force=True`. NVD is rate-limited without an API key — set NVD_API_KEY in the
environment to raise the limit. See data/README.md.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import requests

CACHE_DIR = "data/cache"
ATTACK_ICS_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
)
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 30


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "none"


# --------------------------------------------------------------------------- #
# MITRE ATT&CK for ICS (step 3)
# --------------------------------------------------------------------------- #
def fetch_attack_ics(dest: str = "data/attack_ics.json", force: bool = False) -> str:
    """Download the ATT&CK for ICS STIX bundle to `dest`. Returns the path."""
    if force or not Path(dest).exists():
        resp = requests.get(ATTACK_ICS_URL, timeout=_TIMEOUT)
        resp.raise_for_status()
        Path(dest).write_text(resp.text, encoding="utf-8")
    return dest


def load_attack_ics(path: str = "data/attack_ics.json") -> dict[str, dict]:
    """Parse the STIX bundle into {technique_id: {name, tactics, url, description}}.

    Only real techniques are kept (revoked/deprecated objects are dropped).
    """
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    techniques: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id = url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not ext_id:
            continue
        techniques[ext_id] = {
            "name": obj.get("name", ""),
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
            "url": url,
            "description": obj.get("description", ""),
        }
    return techniques


# --------------------------------------------------------------------------- #
# CISA Known Exploited Vulnerabilities (step 5)
# --------------------------------------------------------------------------- #
def fetch_kev_catalog(cache_dir: str = CACHE_DIR, force: bool = False) -> set[str]:
    """Return the set of CVE IDs in the CISA KEV catalog (cached)."""
    cache = Path(cache_dir) / "kev.json"
    if force or not cache.exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        resp = requests.get(KEV_URL, timeout=_TIMEOUT)
        resp.raise_for_status()
        cache.write_text(resp.text, encoding="utf-8")
    data = json.loads(cache.read_text(encoding="utf-8"))
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


# --------------------------------------------------------------------------- #
# NVD CVE lookup (step 5)
# --------------------------------------------------------------------------- #
def _cvss(cve: dict) -> tuple[float | None, str]:
    """Best-available CVSS base score + severity (prefers v3.1 > v3.0 > v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            return d.get("baseScore"), d.get("baseSeverity", "")
    if metrics.get("cvssMetricV2"):
        m = metrics["cvssMetricV2"][0]
        return m["cvssData"].get("baseScore"), m.get("baseSeverity", "")
    return None, ""


def lookup_cves_by_cpe(
    cpe_hint: str | None,
    kev: set[str] | None = None,
    cache_dir: str = CACHE_DIR,
    limit: int = 20,
    api_key: str | None = None,
) -> list[dict]:
    """Return CVEs for a product. Returns [] when cpe_hint is None.

    NVD is keyed by CPE; exact CPE strings are fiddly, so this first cut uses NVD's
    forgiving keywordSearch over the asset's vendor+product (the version part of the
    hint is dropped — it narrows results too aggressively for keyword matching).
    Results are cached per product under data/cache/. Flags CVEs present in `kev`.

    TODO: tighten to exact `cpeName=cpe:2.3:...` matching once a CPE map is built.
    """
    if not cpe_hint:
        return []
    keyword = " ".join(cpe_hint.split(":")[:2]).strip()  # vendor + product, drop version
    if not keyword:
        return []

    cache = Path(cache_dir) / f"nvd_{_slug(keyword)}.json"
    if cache.exists():
        raw = json.loads(cache.read_text(encoding="utf-8"))
    else:
        params = {"keywordSearch": keyword, "resultsPerPage": limit}
        headers = {}
        key = api_key or os.environ.get("NVD_API_KEY")
        if key:
            headers["apiKey"] = key
        else:
            time.sleep(6)  # NVD asks ~6s between unauthenticated requests
        resp = requests.get(NVD_URL, params=params, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        raw = resp.json()
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(raw), encoding="utf-8")

    kev = kev or set()
    out = []
    for item in raw.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        score, severity = _cvss(cve)
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        out.append({
            "id": cve_id,
            "cvss": score,
            "severity": severity,
            "known_exploited": cve_id in kev,
            "description": desc,
        })
    return out
