# Risk Scoring Rubric (NIST SP 800-30 Rev. 1)

Likelihood and Impact are each scored **0–100 internally** (semi-quantitative, per SP
800-30 Table H-3 — sortable, and the two axes of the risk-matrix scatter), then mapped
to **qualitative bands** and combined into a risk band via the 800-30 **Table I-2**
lookup. The lookup is authoritative for the reported risk band; it does not deflate the
way a normalized `Likelihood × Impact` product does (which pushed every asset to "Low").

## Qualitative bands (SP 800-30 Appendix I)

| Band      | Score range |
|-----------|-------------|
| Very Low  | 0–19        |
| Low       | 20–39       |
| Moderate  | 40–59       |
| High      | 60–79       |
| Very High | 80–100      |

## Risk = f(Likelihood, Impact) — Table I-2 lookup

Rows = Likelihood band, columns = Impact band; cell = Risk band.

| Likelihood ↓ / Impact → | Very Low | Low | Moderate | High | Very High |
|-------------------------|----------|-----|----------|------|-----------|
| **Very High**           | Very Low | Low | Moderate | High | Very High |
| **High**                | Very Low | Low | Moderate | High | Very High |
| **Moderate**            | Very Low | Low | Moderate | Moderate | High   |
| **Low**                 | Very Low | Low | Low      | Low  | Moderate  |
| **Very Low**            | Very Low | Very Low | Very Low | Low | Low   |

## Likelihood factors

Folds 800-30's *likelihood of initiation* × *likelihood of adverse impact*.

| Factor                  | Signal                                                        |
|-------------------------|--------------------------------------------------------------|
| Exposure                | Attack-path distance from an entry node / Purdue depth; closer to IT/OT boundary = higher |
| Protocol authentication | Unauthenticated protocol = higher                            |
| Known-exploited         | CVE present in CISA KEV = largest single bump                |

## Impact factors

800-30 Appendix H — harm to operations / assets.

| Factor            | Signal                                                  |
|-------------------|---------------------------------------------------------|
| Process criticality | Does the asset directly affect the physical process / safety |
| Blast radius        | Count of downstream-dependent assets (from the graph)  |

## Notes

- CVSS scores are used where CVEs are attached, contributing to the likelihood/impact factors.
- The exact factor weights and normalization live in `src/scoring.py`; keep this file in sync
  so every score remains traceable to a documented rubric.

## References

- NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments*
- NIST SP 800-82 Rev. 3, *Guide to Operational Technology (OT) Security*
