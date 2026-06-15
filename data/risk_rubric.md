# Risk Scoring Rubric

## What comes from the standard, and what is engineering judgment

Be clear about provenance — it matters for a security deliverable:

- **From NIST SP 800-30 Rev. 1 (the standard):** the qualitative band scale (Appendix I),
  and the **Table I-2 lookup** that combines Likelihood and Impact bands into a Risk band.
  These are used verbatim.
- **Engineering judgment (a transparent heuristic):** the *factors* that feed Likelihood and
  Impact, and the **weights** assigned to them. 800-30 defines the factor taxonomy but does
  not prescribe numeric weights for a specific system — those are choices made here. They are
  documented below and, critically, **validated as robust** (see Sensitivity): the priority
  ranking does not hinge on the exact numbers.

This is deliberately *not* "NIST says the weights are 0.4/0.3/0.3." It is "the combination
rule is NIST's; the weights are ours, justified and stress-tested."

## Pipeline

Likelihood and Impact are each scored **0–100** (semi-quantitative, per SP 800-30 Table
H-3 — sortable, and the two axes of the risk-matrix scatter), mapped to **qualitative
bands**, then combined into a Risk band via the **Table I-2** lookup. The lookup is
authoritative for the reported band; it does not deflate the way a normalized
`Likelihood × Impact` product does (which pushed every asset to "Low").

## Qualitative bands (SP 800-30 Appendix I)

| Band | Very Low | Low | Moderate | High | Very High |
|------|----------|-----|----------|------|-----------|
| Score range | 0–19 | 20–39 | 40–59 | 60–79 | 80–100 |

## Risk = f(Likelihood, Impact) — Table I-2 lookup

Rows = Likelihood band, columns = Impact band; cell = Risk band.

| Likelihood ↓ / Impact → | Very Low | Low | Moderate | High | Very High |
|-------------------------|----------|-----|----------|------|-----------|
| **Very High**           | Very Low | Low | Moderate | High | Very High |
| **High**                | Very Low | Low | Moderate | High | Very High |
| **Moderate**            | Very Low | Low | Moderate | Moderate | High   |
| **Low**                 | Very Low | Low | Low      | Low  | Moderate  |
| **Very Low**            | Very Low | Very Low | Very Low | Low | Low   |

## Likelihood factors and weights

Folds 800-30's *likelihood of initiation* × *likelihood of adverse impact*. Weighted sum
to 0–100.

| Factor (weight) | Signal (0–100) | Why this weight |
|-----------------|----------------|-----------------|
| Exposure (**0.60**) | `100 × 0.7^d`, d = hops from the nearest entry node on the reachability graph | Highest weight: reachability is the dominant determinant of whether a capable actor can act at all. Decay 0.7 ≈ "each enforced hop roughly a third harder." |
| Protocol auth (**0.40**) | 100 if the asset speaks an unauthenticated protocol, else 20 | Unauthenticated OT protocols are the defining ICS weakness, but secondary to being reachable in the first place. |

A former third likelihood factor (known-exploited / CVSS, weight 0.30) was **removed** after
an ablation (`experiments/ablation_followup.py`) showed it changed no asset's band or rank —
even the asset carrying a KEV CVE. See the KEV escalator below.

## Impact factors and weights

800-30 Appendix H — harm to operations / assets. Weighted sum to 0–100.

| Factor (weight) | Signal (0–100) | Why this weight |
|-----------------|----------------|-----------------|
| Process criticality (**0.60**) | by Purdue level: L0/L1 = 100, L2 = 60, L3 = 40, DMZ = 30, L4 = 20, L5 = 10 | Dominant: physical-process impact is the whole point of ICS risk. A controller is consequential regardless of how many neighbors it has. |
| Blast radius (**0.40**) | downstream-dependent assets below it in the Purdue stack, normalized | Secondary amplifier: a controller that many process assets depend on is worse than an isolated one. |

## Exploitation escalator (post-lookup)

After the Table I-2 risk band is computed, an asset is escalated one band (capped at Very
High) if any of its CVEs is either **actively exploited (CISA KEV)** or in the **top EPSS
percentile** (≥ 0.95). KEV reflects confirmed exploitation (CISA BOD 22-01's must-patch
posture). EPSS is FIRST.org's published machine-learning estimate of 30-day exploitation
probability; its raw scores are right-skewed, so the percentile is the threshold. EPSS catches
CVEs that are likely to be exploited but not yet KEV-listed: on the water plant it escalates
three assets (`scada_server`, `operator_hmi`, `distribution_rtu`) that KEV alone does not, so
the two signals are complementary. Applied as a discrete escalation because an ablation showed
the old weighted CVE factor moved no result.

**Caveat — escalation ignores version confirmation.** The escalator fires on any attached
KEV / high-EPSS CVE regardless of its `version_status`, including product-level matches where
the asset's installed version could not be confirmed affected. This is deliberately
conservative (an exploited CVE for *some* version of the product is worth flagging), but it
means escalation can fire hardest exactly where version matching was weakest. The briefing
marks each unconfirmed CVE as *(version not confirmed)* so the analyst can judge.

## Sensitivity — does the ranking depend on the exact weights?

`scoring.sensitivity()` re-scores under every combination of the likelihood and impact
weights perturbed by **±20%** and measures stability. Results on the shipped architectures:

| Architecture | Highest-risk asset stable | Top-3 set stable | Per-asset band stable |
|--------------|---------------------------|------------------|-----------------------|
| Transit signaling | **100%** | 89% | 78% |
| Water treatment | **100%** | 89% | 71% |

**Reading.** The decision-relevant output — *which assets to harden first* — is robust:
the single highest-priority asset is invariant, and the top-3 set is 89% stable (churn confined
to near-tied, same-band assets). Per-asset *bands* are more weight-sensitive (~75%) than the
earlier 3-factor model — the old 92% was partly an artifact of the inert third factor (usually
0) dampening variance; removing it exposed the true band sensitivity. The trade-off: the
priority ranking is robust, individual bands are a heuristic.

`test_scoring.py` enforces this (top-1 = 100%, top-3 set ≥ 80%, band ≥ 70%, bounded contender
set), so a change that broke the priority robustness would fail CI.

## References

- NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments* (bands Appendix I; Table I-2; factors Appendix G/H)
- NIST SP 800-82 Rev. 3, *Guide to Operational Technology (OT) Security*
