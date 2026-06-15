"""NVD CVE / CISA KEV / MITRE ATT&CK for ICS data sources.

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
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
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


def _mitre_ref(obj) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def load_attack_mitigations(path: str = "data/attack_ics.json") -> dict[str, list[dict]]:
    """Parse {technique_id: [mitigation {id, name, url}]} from the ATT&CK bundle.

    Joins ATT&CK course-of-action (mitigation) objects to techniques via `mitigates`
    relationships. Revoked/deprecated mitigations are dropped.
    """
    objs = json.loads(Path(path).read_text(encoding="utf-8")).get("objects", [])
    mitigations: dict[str, dict] = {}
    technique_extid: dict[str, str] = {}
    for o in objs:
        t = o.get("type")
        if t == "course-of-action" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            ext, url = _mitre_ref(o)
            if ext and ext.startswith("M"):
                mitigations[o["id"]] = {"id": ext, "name": o.get("name", ""), "url": url}
        elif t == "attack-pattern":
            ext, _ = _mitre_ref(o)
            if ext:
                technique_extid[o["id"]] = ext

    out: dict[str, list[dict]] = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates":
            mit = mitigations.get(o.get("source_ref"))
            tech = technique_extid.get(o.get("target_ref"))
            if mit and tech and mit["id"] not in {m["id"] for m in out.get(tech, [])}:
                out.setdefault(tech, []).append(mit)
    for tech in out:
        out[tech].sort(key=lambda m: m["id"])
    return out


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


def _nvd_get(url: str, params: dict, api_key: str | None = None, retries: int = 3) -> dict:
    """GET an NVD endpoint, respecting the rate limit and retrying transient failures."""
    headers = {}
    key = api_key or os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    last: Exception | None = None
    for attempt in range(retries):
        if not key:
            time.sleep(6)  # NVD asks ~6s between unauthenticated requests
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as e:
            last = e
            time.sleep(2 * (attempt + 1))  # back off before retrying
    raise last if last is not None else RuntimeError("NVD request failed")


def _resolve_one(keyword: str, cache_dir: str, api_key: str | None) -> str | None:
    """Single CPE-dictionary lookup for an exact keyword (cached). Top match -> base."""
    cache = Path(cache_dir) / f"cpe_{_slug(keyword)}.json"
    if cache.exists():
        data = json.loads(cache.read_text(encoding="utf-8"))
    else:
        data = _nvd_get(NVD_CPE_URL, {"keywordSearch": keyword, "resultsPerPage": 5}, api_key)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(data), encoding="utf-8")
    products = data.get("products", [])
    if not products:
        return None
    return ":".join(products[0]["cpe"]["cpeName"].split(":")[:5])  # cpe:2.3:part:vendor:product


def resolve_cpe_base(keyword: str, cache_dir: str = CACHE_DIR,
                     api_key: str | None = None) -> str | None:
    """Resolve a product keyword to its CPE base `cpe:2.3:<part>:<vendor>:<product>`.

    Queries the NVD CPE dictionary (precise — far better than a free-text CVE search).
    Over-specific names (e.g. a catalog number like "ControlLogix 1756-L61") often miss,
    so this falls back by dropping trailing tokens until the dictionary matches. Cached.
    """
    words = keyword.split()
    for end in range(len(words), 1, -1):  # full keyword, then progressively shorter
        base = _resolve_one(" ".join(words[:end]), cache_dir, api_key)
        if base:
            return base
    return None


def _vparts(v) -> list[int] | None:
    parts = []
    for p in str(v).replace("-", ".").split("."):
        if not p.isdigit():
            return None
        parts.append(int(p))
    return parts or None


def _vcmp(a, b) -> int | None:
    """Compare dotted-numeric versions: -1/0/1, or None if either is unparseable."""
    pa, pb = _vparts(a), _vparts(b)
    if pa is None or pb is None:
        return None
    n = max(len(pa), len(pb))
    pa, pb = pa + [0] * (n - len(pa)), pb + [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def _match_affects(asset_version: str, m: dict) -> bool | None:
    """Does an NVD cpeMatch include asset_version? True / False / None (undeterminable)."""
    bounds = {"versionStartIncluding": ">=", "versionStartExcluding": ">",
              "versionEndIncluding": "<=", "versionEndExcluding": "<"}
    present = {k: m[k] for k in bounds if k in m}
    if not present:
        crit_version = (m.get("criteria", "").split(":") + [""] * 6)[5]
        if crit_version in ("*", "-", ""):
            return True  # applies to all versions
        c = _vcmp(asset_version, crit_version)
        return None if c is None else c == 0
    inside = True
    for key, op in bounds.items():
        if key not in present:
            continue
        c = _vcmp(asset_version, present[key])
        if c is None:
            return None
        inside &= {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0}[op]
    return inside


def _version_status(asset_version: str, cve: dict, base: str) -> str:
    """`confirmed` / `not-affected` / `unconfirmed` for asset_version vs a CVE's CPE config."""
    if not asset_version:
        return "unconfirmed"
    vendor_product = ":".join(base.split(":")[3:5])
    results = [
        _match_affects(asset_version, m)
        for conf in cve.get("configurations", [])
        for node in conf.get("nodes", [])
        for m in node.get("cpeMatch", [])
        if m.get("vulnerable") and vendor_product in m.get("criteria", "")
    ]
    if any(r is True for r in results):
        return "confirmed"
    if results and all(r is False for r in results):
        return "not-affected"
    return "unconfirmed"


def lookup_cves_by_cpe(
    cpe_hint: str | None,
    kev: set[str] | None = None,
    cache_dir: str = CACHE_DIR,
    limit: int = 10,
    api_key: str | None = None,
) -> list[dict]:
    """Return the worst CVEs affecting a product, matched by CPE. [] if cpe_hint is None.

    Resolves the asset's vendor+product to a CPE base via the NVD CPE dictionary, then
    queries CVEs by `virtualMatchString`. Each CVE is checked against the asset's *version*:
    CVEs the version is confirmed not to be affected by are dropped, and the rest carry a
    `version_status` of `confirmed` or `unconfirmed` (product-level match, version not
    determinable). Results are cached, KEV-flagged, sorted by CVSS; the top `limit` returned.
    """
    if not cpe_hint:
        return []
    keyword = " ".join(cpe_hint.split(":")[:2]).strip()  # vendor + product
    base = resolve_cpe_base(keyword, cache_dir, api_key)
    if not base:
        return []

    cache = Path(cache_dir) / f"nvd_{_slug(base)}.json"
    if cache.exists():
        raw = json.loads(cache.read_text(encoding="utf-8"))
    else:
        raw = _nvd_get(NVD_URL, {"virtualMatchString": base, "resultsPerPage": 50}, api_key)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(raw), encoding="utf-8")

    asset_version = (cpe_hint.split(":") + ["", "", ""])[2]
    kev = kev or set()
    out = []
    for item in raw.get("vulnerabilities", []):
        cve = item["cve"]
        status = _version_status(asset_version, cve, base)
        if status == "not-affected":
            continue  # version-aware: drop CVEs the asset's version is not subject to
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
            "version_status": status,
            "description": desc,
        })
    # worst first (KEV, then CVSS); keep the top `limit`
    out.sort(key=lambda c: (c["known_exploited"], c["cvss"] or 0), reverse=True)
    return out[:limit]


def fetch_epss(cve_ids, cache_dir: str = CACHE_DIR, force: bool = False) -> dict:
    """Return {cve_id: {epss, percentile, date}} from the FIRST.org EPSS API (cached).

    EPSS (Exploit Prediction Scoring System) is a published machine-learning model that
    estimates the probability a CVE will be exploited in the next 30 days. Scores are heavily
    right-skewed, so the percentile is the more useful signal. Unknown CVEs map to None.
    """
    ids = sorted(set(cve_ids))
    if not ids:
        return {}
    cache = Path(cache_dir) / "epss.json"
    cached = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() and not force else {}
    missing = [c for c in ids if c not in cached]
    for i in range(0, len(missing), 100):  # EPSS API takes a comma-separated batch
        batch = missing[i:i + 100]
        resp = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=_TIMEOUT)
        resp.raise_for_status()
        scored = {r["cve"]: {"epss": float(r["epss"]), "percentile": float(r["percentile"]),
                             "date": r.get("date")} for r in resp.json().get("data", [])}
        for c in batch:
            cached[c] = scored.get(c)  # None if EPSS has no score for it
    if missing:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(cached), encoding="utf-8")
    return {c: cached[c] for c in ids if cached.get(c)}


def attack_provenance(path: str = "data/attack_ics.json") -> str:
    """Provenance for the ATT&CK bundle: source + fetch date (the bundle is rolling master)."""
    from datetime import datetime, timezone

    p = Path(path)
    if not p.exists():
        return "not loaded"
    fetched = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime("%Y-%m-%d")
    return f"MITRE CTI master, fetched {fetched}"


def load_cve_snapshot(path: str = "data/cve_snapshot.json") -> dict:
    """Load the committed CVE snapshot {cpe_hint: [cves]} (new {_meta, products} or legacy flat)."""
    p = Path(path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get("products", data)


def load_cve_snapshot_meta(path: str = "data/cve_snapshot.json") -> dict:
    """Provenance metadata for the CVE snapshot (generation date, KEV date/count)."""
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8")).get("_meta", {})
