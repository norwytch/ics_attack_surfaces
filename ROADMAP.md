# Roadmap

Known limitations and planned improvements, in priority order. This is a deliberate
record of where the model is honest-but-shallow today, and what would make it credible
as a security tool rather than a demonstration.

Tiers are ordered by impact on trustworthiness, not by effort.

---

## Tier 1 — Credibility (do before presenting as a real capability)

### 1. Prove the framework generalizes — add a second reference architecture — DONE
**Problem.** The README pitched a *framework* that "generalizes to any ICS," but there was
exactly one hand-authored architecture, and the mapping rules were implicitly tuned to it.
**What was done.** Added [data/water_treatment.yaml](data/water_treatment.yaml) — a
structurally different model (Rockwell/GE/OSIsoft/Inductive Automation gear, EtherNet/IP +
DNP3, Oldsmar-style remote-access-bypasses-DMZ design). Added `--arch`/`--out` to the
pipeline. Running it surfaced the predicted hidden assumption: the rules only covered
Modbus/S7comm, so DNP3 and EtherNet/IP assets (including a critical RTU and the dosing PLC)
got few or no techniques. **Fix:** generalized the protocol rules to cover the common
unauthenticated OT protocols and split them by capability (command/parameter vs.
controller-tasking vs. program-download). This also *removed* an over-assignment — the
SCADA server and field sensors were wrongly getting "Modify Controller Tasking."
**Guard.** `test_ot_assets_are_never_left_uncovered` runs over both architectures and fails
if any OT-protocol asset maps to zero techniques. Full suite green.
**Caveat / follow-up.** The water model exposes a *topology* limitation that #2 addresses:
the remote-access host reaches L2 directly, and the model can't yet express that the DMZ
*should* have stopped it — it's a connection, not an enforced boundary.

### 2. Make attack paths security-meaningful, not just topological — DONE
**Problem.** Path-finding ran on an **undirected** graph where every edge was equally
traversable; the DMZ was a *node*, not an enforced boundary, so "shortest path" was
topology, not attacker reachability.
**What was done.** Added a `segmentation` policy to the architecture schema (zone-to-zone
boundaries with per-protocol allow-lists; default-allow keeps old models working).
`Architecture.reachability_graph()` builds a **directed** graph containing only the edges
the policy permits, weighted by hop difficulty (unauthenticated targets are cheaper).
Attack-path and chokepoint analysis now run on that graph, so denied edges are absent and
paths are ranked by summed difficulty (`cost`), not hop count. Added
`segmentation_violations()` to flag permitted edges that cross the IT/OT boundary directly,
skipping the DMZ. Both reference plants got policies: the transit plant is properly
segmented (clean), the water plant leaves the remote-access→SCADA link un-firewalled and
the briefing flags it as the top segmentation fix (the Oldsmar pattern).
**Done when — met.** `test_deny_boundary_blocks_path` shows a path vanishing when a
boundary denies it; `test_removing_the_rule_restores_the_path` shows the set change; the
water briefing reports the bypass while the transit one reports none. Full suite (28) green.
**Follow-up.** Protocol-on-edge is approximated by the destination's protocols (no
per-connection protocol field yet); good enough for boundary enforcement, refine if needed.

### 3. Own the scoring model — justify the weights or reframe them — DONE
**Problem.** The likelihood/impact weights were invented numbers presented in NIST 800-30
language; the Table I-2 lookup is from the standard, but its *inputs* were not, implying a
rigor that wasn't there.
**What was done.** Did both (a) and (b). [data/risk_rubric.md](data/risk_rubric.md) now opens
with an explicit provenance split — the band scale and Table I-2 combination are NIST's; the
factors and weights are a documented engineering heuristic — and justifies every weight with
a sentence of reasoning. Made the weights injectable in `scoring.py` and added
`sensitivity()`, which re-scores under all 243 combinations of ±20% weight perturbations and
reports ranking/band stability.
**Done when — met (honestly).** The sensitivity result is *not* a clean 100%, and the rubric
says so: the highest-priority asset is 100% stable and bands move <10%, but the top-3 *set*
churns at rank #3 between two same-band near-ties (transit 76%, water 89% set-stable). The
honest conclusion — *which assets to harden first is robust to the weights; fine-grained
ordering among equally-banded assets is not* — is documented and enforced by
`test_scoring_ranking_is_robust_to_weight_perturbation` (top-1 = 100%, band ≥ 90%, bounded
contender set). Full suite (30) green.

---

**Tier 1 complete.** All three credibility items done. The model now: runs on two
structurally different architectures, treats attack paths as policy-respecting reachability
rather than topology, and uses a scoring model whose conclusions are stress-tested against
its own weight choices.

---

## Tier 2 — Make the strong features actually strong

### 4. CVE matching: exact CPE, and enrichment on by default
**Problem.** The flagship "real data" feature is the weakest code: `lookup_cves_by_cpe` in
[src/data_sources.py](src/data_sources.py) uses NVD `keywordSearch` over vendor+product
(self-labeled approximate), which yields false positives and misses CPE-specific matches.
Worse, it is opt-in (`--cves`), so the **default briefing ships with an empty CVE
section** — the best feature doesn't run unless you know to ask.
**Plan.** Build proper CPE 2.3 strings (`cpe:2.3:a:vendor:product:version:...`) and query
NVD by `cpeName`/`virtualMatchString`. Maintain a small vendor/product→CPE map for the
modeled gear. Commit a cached enriched run so the default briefing shows real CVEs + KEV
flags without a live call.
**Done when.** The default `python -m src.pipeline` briefing contains real, correctly
matched CVEs with KEV flags, sourced from cache.

### 5. Confidence-weighted threat-trend correlation
**Problem.** [src/trends.py](src/trends.py) is a set intersection: sharing ≥1 technique
with a campaign lists the asset under it. Sharing "Program Download" with Stuxnet does not
make a transit plant Stuxnet-vulnerable, but the briefing presents a one-technique overlap
with the same weight as a real finding.
**Plan.** Score each correlation (fraction of the campaign's characteristic techniques the
asset exposes, weighted by technique criticality), apply a threshold, and present a
confidence level instead of a binary match. Say explicitly what a match does and does not
imply.
**Done when.** Correlations carry a score and a stated threshold, and weak single-technique
overlaps are demoted or labeled low-confidence.

### 6. Verified citations + an explicit scope/limitations section
**Problem.** The threat-trend summaries and citations are not independently verified (a note
defers this to a human), and the briefing speaks with uniform confidence with no statement
of blind spots or false-positive posture — exactly what mature security work states up front.
**Plan.** Verify each citation supports its claim and record the check. Add a "Scope &
Limitations" section to the generated briefing: what the model covers, what it does not
(no live traffic, no config audit, topology-based assumptions), and how to read the
confidence levels.
**Done when.** Every citation is verified, and the briefing ends with a limitations section.

---

## Tier 3 — Engineering hygiene

### 7. Packaging and configuration
**Problem.** No `pyproject.toml`; not installable as a package; `src.` imports assume
run-from-repo-root; `data/` and `results/` paths are hardcoded.
**Plan.** Add `pyproject.toml`, make it `pip install -e .`-able with a console entry point,
and route paths through config/CLI args rather than literals.
**Done when.** `pip install -e . && ics-modeler --arch ...` works from any directory.

### 8. CI, linting, type-checking, and a lockfile
**Problem.** No CI, no linter/formatter/type-checker config despite type hints everywhere,
and `requirements.txt` has bounds but no lockfile, so "reproducible" is claimed not proven.
**Plan.** Add ruff + mypy + pytest in a CI workflow on push/PR, and pin a lockfile.
**Done when.** CI is green on a clean checkout and fails on a lint/type/test regression.

### 9. Deepen the tests beyond smoke checks
**Problem.** The 19 tests are mostly structural ("briefing contains these headings",
"scores in range"). Few pin actual values or guard the scoring logic against regression;
the Table I-2 matrix gets ~4 of 25 cells checked.
**Plan.** Add value-pinning tests for representative scores, full Table I-2 coverage, and
property-based tests (e.g. monotonicity: more exposure never lowers likelihood). Add a
golden-file test for the generated briefing.
**Done when.** Scoring changes that alter rankings break a test, and the matrix is fully
covered.

---

## Explicitly out of scope (for now)

- Live network/traffic analysis — this is a static, model-based tool by design.
- Real-asset/config ingestion — input is a hand-authored model, not a discovered network.
- Automated remediation — recommendations are advisory.

Stating these is deliberate: the tool's value depends on being clear about what it does
*not* claim to do.
