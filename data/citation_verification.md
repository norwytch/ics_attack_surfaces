# Citation Verification Log

Threat-trend citations ([threat_trends.yaml](threat_trends.yaml)) were checked against the
claims they support. Method: automated fetch of each URL and a content check that the
source discusses the campaign and the cited behaviour. Verifying found real link rot in the
references MITRE attaches to these campaigns — several were updated or replaced.

**Checked:** 2026-06-11.

| Campaign | Source | Original URL status | Action |
|----------|--------|---------------------|--------|
| Stuxnet | Symantec W32.Stuxnet Dossier | 200 — **content verified** (Stuxnet / S7 PLCs) | kept |
| Stuxnet | CISA advisory ICSA-10-272-01 | host moved (us-cert → cisa.gov); 403 to automated fetch | URL host updated; canonical, manual review |
| Stuxnet | Langner, *To Kill a Centrifuge* | 301 → otbase.com (company rebranded); no Wayback snapshot | **dropped** (two solid sources remain) |
| TRITON/TRISIS | FireEye/Mandiant disclosure | 301 chain → Google Cloud blog; **content verified** ("attack framework built to interact with Triconex SIS controllers") | URL updated to Google Cloud |
| TRITON/TRISIS | Dragos TRISIS report | original 404 (site reorganized) | replaced with Wayback snapshot (2018-11-25) |
| TRITON/TRISIS | CISA MAR-17-352-01 (HatMan) | host moved (us-cert → cisa.gov); 403 to automated fetch | URL host updated; canonical, manual review |
| Industroyer | ESET Win32/Industroyer | 301 → esetstatic.com; reachable (PDF body not auto-extractable) | URL host updated |
| Industroyer | Dragos CRASHOVERRIDE | original 404 (site reorganized) | replaced with Wayback snapshot (2025-08-20) |

## Notes

- **"Manual review"** entries (the two CISA documents) are the canonical government sources;
  CISA returns HTTP 403 to automated fetchers, so content could not be auto-confirmed — the
  URLs are correct and stable but warrant a human eyeball before any external publication.
- The technique *mappings* themselves come from MITRE's curated ATT&CK software objects
  (S0603 / S1009 / S0604) and are checked for currency by
  `test_campaign_techniques_are_current`.
- Re-run this check periodically: security-vendor reports move, and KEV/CVE data drifts.
