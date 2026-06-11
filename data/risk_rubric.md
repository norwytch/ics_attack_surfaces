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
| Exposure (**0.40**) | `100 × 0.7^d`, d = hops from the nearest entry node on the reachability graph | Highest weight: reachability is the dominant determinant of whether a capable actor can act at all. Decay 0.7 ≈ "each enforced hop roughly a third harder." |
| Protocol auth (**0.30**) | 100 if the asset speaks an unauthenticated protocol, else 20 | Unauthenticated OT protocols are the defining ICS weakness, but secondary to being reachable in the first place. |
| Known-exploited (**0.30**) | 100 if any attached CVE is in CISA KEV; else worst-CVSS×10; else 0 | A live, exploited vuln is a strong signal — weighted equal to auth, below exposure because a KEV CVE on an unreachable asset is still low-likelihood. |

## Impact factors and weights

800-30 Appendix H — harm to operations / assets. Weighted sum to 0–100.

| Factor (weight) | Signal (0–100) | Why this weight |
|-----------------|----------------|-----------------|
| Process criticality (**0.60**) | by Purdue level: L0/L1 = 100, L2 = 60, L3 = 40, DMZ = 30, L4 = 20, L5 = 10 | Dominant: physical-process impact is the whole point of ICS risk. A controller is consequential regardless of how many neighbors it has. |
| Blast radius (**0.40**) | downstream-dependent assets below it in the Purdue stack, normalized | Secondary amplifier: a controller that many process assets depend on is worse than an isolated one. |

CVSS scores, where CVEs are attached, feed the known-exploited factor.

## Sensitivity — does the ranking depend on the exact weights?

`scoring.sensitivity()` re-scores under every combination of the likelihood and impact
weights perturbed by **±20%** (243 weight settings) and measures stability. Results on the
shipped architectures:

| Architecture | Highest-risk asset stable | Per-asset band stable | Top-3 set stable |
|--------------|---------------------------|-----------------------|------------------|
| Transit signaling | **100%** | 92% | 76% |
| Water treatment | **100%** | 92% | 89% |

**Honest reading.** The single highest-priority asset is invariant to the weights, and bands
move in <10% of cases. The top-3 *set* is not perfectly stable — but the only churn is a
**near-tie at rank #3 between two assets in the same risk band** (transit:
`track_circuit_sensor` ↔ `scada_server`). So the headline conclusion — *which assets to
harden first* — is robust to the weights; only fine-grained ordering among equally-banded
assets shifts. The weights are a defensible heuristic, not load-bearing magic numbers.

`test_scoring.py` enforces this (top-1 stability = 100%, band stability ≥ 90%, bounded
contender set), so a future weight change that broke the robustness would fail CI.

## References

- NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments* (bands Appendix I; Table I-2; factors Appendix G/H)
- NIST SP 800-82 Rev. 3, *Guide to Operational Technology (OT) Security*
