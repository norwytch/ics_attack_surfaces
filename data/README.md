# Data Sources

All data here is public. Files marked *generated/downloaded* are cached to disk and
refreshed deliberately (see below); the rest are hand-authored.

| File                        | Source / how to refresh |
|-----------------------------|-------------------------|
| `reference_architecture.yaml` | Hand-authored. A hypothetical plant built from public commercial products. |
| `mapping_rules.yaml`          | Hand-authored. Asset→technique rules; extend deliberately. |
| `risk_rubric.md`              | Hand-authored. NIST SP 800-30 scoring rubric. |
| `threat_trends.yaml`          | Curated, **cited**. Technique lists are a subset of MITRE's software mappings (regenerate the full lists with `python -m scripts.harvest_trends`); sources are MITRE's canonical references. Real campaigns only — never fabricate. |
| `attack_ics.json`             | Downloaded — MITRE ATT&CK for ICS (STIX 2.0 JSON) from the MITRE CTI GitHub repo. |
| `cache/`                      | Downloaded — cached NVD CVE / CISA KEV responses (gitignored). |

## Refresh procedure

- **MITRE ATT&CK for ICS:** fetch the STIX JSON from MITRE's public CTI repo; parse with
  `mitreattack-python` or directly. Save as `attack_ics.json`.
- **NVD CVEs:** queried by CPE (vendor:product:version) per asset. Rate-limited without an
  API key — cache responses under `data/cache/` and refresh on demand, not per run.
- **CISA KEV:** single downloadable JSON catalog; used to flag actively-exploited CVEs.

## References

- MITRE ATT&CK for ICS — https://attack.mitre.org/matrices/ics/
- CISA ICS Advisories — https://www.cisa.gov/news-events/cybersecurity-advisories
- CISA KEV Catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD CVE API — https://nvd.nist.gov/developers/vulnerabilities
