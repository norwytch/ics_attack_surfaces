# Data Sources

All data here is public. Files marked *generated/downloaded* are cached to disk and
refreshed deliberately (see below); the rest are hand-authored.

| File                        | Source / how to refresh |
|-----------------------------|-------------------------|
| `reference_architecture.yaml` | Hand-authored. A hypothetical plant built from public commercial products. |
| `mapping_rules.yaml`          | Hand-authored. Asset→technique rules; extend deliberately. |
| `risk_rubric.md`              | Hand-authored. NIST SP 800-30 scoring rubric. |
| `threat_trends.yaml`          | Curated, **cited**. Technique lists are a subset of MITRE's software mappings (regenerate the full lists with `python -m scripts.harvest_trends`); sources are MITRE's canonical references. Real campaigns only — never fabricate. |
| `attack_ics.json`             | Downloaded — MITRE ATT&CK for ICS (STIX 2.0 JSON) from the MITRE CTI GitHub repo (gitignored). |
| `cve_snapshot.json`           | Committed — per-product CVE snapshot (CPE-matched, version-filtered, KEV-flagged, EPSS-scored) used for offline briefings. Refresh with `python -m scripts.build_cve_snapshot`. |
| `cache/`                      | Downloaded — cached NVD CPE/CVE, CISA KEV, and EPSS responses (gitignored). |

## Refresh procedure

- **MITRE ATT&CK for ICS:** fetch the STIX JSON from MITRE's public CTI repo; parse with
  `mitreattack-python` or directly. Save as `attack_ics.json`.
- **NVD CVEs:** each asset's vendor+product is resolved to a CPE base via the NVD CPE
  dictionary (`resolve_cpe_base`, with a trailing-token fallback for over-specific catalog
  names), then CVEs are queried by `virtualMatchString`. Rate-limited without an API key —
  responses cache under `data/cache/`; `scripts.build_cve_snapshot` distills the committed
  `cve_snapshot.json`.
- **CISA KEV:** single downloadable JSON catalog; used to flag actively-exploited CVEs.
- **EPSS:** the FIRST.org EPSS API (`fetch_epss`) returns a per-CVE exploitation probability
  and percentile; the snapshot stores both, and the percentile drives the band escalator.

## References

- MITRE ATT&CK for ICS — https://attack.mitre.org/matrices/ics/
- CISA ICS Advisories — https://www.cisa.gov/news-events/cybersecurity-advisories
- CISA KEV Catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD CVE API — https://nvd.nist.gov/developers/vulnerabilities
- FIRST.org EPSS — https://www.first.org/epss/
