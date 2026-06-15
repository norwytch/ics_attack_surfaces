# Roadmap

Known limitations and planned improvements, in priority order. It records where the model is
shallow today and what would make it credible as a security tool rather than a demonstration.

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
**Done when — met.** The sensitivity result is *not* a clean 100%, and the rubric
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

### 4. CVE matching: exact CPE, and enrichment on by default — DONE
**Problem.** CVE matching used NVD `keywordSearch` over free text (approximate, false
positives) and was opt-in, so the default briefing shipped with an empty CVE section.
**What was done.** `resolve_cpe_base` now resolves each asset's vendor+product to a CPE
base via the **NVD CPE dictionary** (with a trailing-token fallback for over-specific
catalog names like "ControlLogix 1756-L61"), then CVEs are queried by `virtualMatchString`
on that base — precise vendor/product matching, sorted by KEV-then-CVSS. Added
`scripts/build_cve_snapshot.py`, which distills a committed `data/cve_snapshot.json`
(CPE-matched, KEV-flagged) for every product in both plants. The pipeline loads that
snapshot **by default (offline)**; `--cves` refreshes live. Added retry/backoff to the NVD
client for transient timeouts.
**Done when — met.** `python -m ics_modeler.pipeline` (no flags) now shows real CVEs with CVSS and
KEV flags — e.g. the water plant's `dosing_plc` carries CVE-2021-22681 (9.8) flagged KEV,
and that signal flows into the likelihood score. Tests assert the snapshot is non-empty and
the default briefing attaches CVEs. Full suite (32) green.

### 5. Confidence-weighted threat-trend correlation — DONE
**Problem.** Correlation was a set intersection — sharing ≥1 technique listed the asset under
the campaign, presenting a one-technique overlap with the same weight as a real finding.
**What was done.** `map_campaigns_to_exposure` now computes **coverage** (the fraction of a
campaign's characteristic techniques the architecture exposes) and a derived **confidence**
band (High ≥0.6 / Moderate ≥0.4 / Low). Per-asset matches carry their own `fraction`. The
briefing prints confidence and an explicit caveat that a match means *shared techniques, not
vulnerability to the specific malware*.
**Done when — met.** On the water plant, Stuxnet reads High (60%), TRITON Moderate (40%), and
Industroyer's single-technique overlap is demoted to **Low (20%)** — exactly the weak
finding that used to look equal to a real one. `test_campaign_confidence_reflects_coverage`
pins the behaviour.

### 6. Verified citations + an explicit scope/limitations section — DONE
**Problem.** Threat-trend citations were unverified, and the briefing spoke with uniform
confidence with no statement of blind spots.
**What was done.** (a) Automated-fetched and content-checked every citation; recorded results
in [data/citation_verification.md](data/citation_verification.md). Verification found real
link rot in MITRE's references — the FireEye/Triton URL now lives on Google Cloud (content
re-verified there), two Dragos PDFs 404'd (replaced with Wayback snapshots), Langner's report
fully rotted (dropped; two solid Stuxnet sources remain), and CISA host URLs were updated.
(b) Added a **Scope & limitations** section to every briefing — model-not-network, paths-are-
reachability-not-exploits, heuristic weights, point-in-time CVEs, trend-matches-mean-shared-
techniques.
**Done when — met.** Every citation was checked and the log records the method and
finding; two CISA government URLs return 403 to bots and are flagged for a human eyeball
before external publication. The briefing now ends with a limitations section.

---

**Tier 2 complete.** The flagship CVE feature works precisely and by default; trend
correlation carries confidence instead of false equivalence; and citations are verified
(with link rot fixed) while the briefing states its own blind spots.

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

### 7. Packaging and configuration — DONE
**Problem.** No `pyproject.toml`; not installable; `src.` imports; hardcoded paths.
**What was done.** Renamed the package `src/` → `ics_modeler/` (a real importable name).
Added `pyproject.toml` with accurate dependencies (dropped unused `pandas`/`graphviz`,
added the previously-undeclared `numpy`), a `dev` extra, and an `ics-modeler` console entry
point. `pip install -e ".[dev]"` works; the CLI takes `--arch`/`--rules`/`--trends`/`--out`
so paths are arguments, not literals.
**Done when — met.** `ics-modeler --arch data/water_treatment.yaml` runs from an installed
package.

### 8. CI, linting, type-checking, and a lockfile — DONE
**Problem.** No CI, no linter/type-checker config, no lockfile.
**What was done.** Added ruff + mypy config in `pyproject.toml`, a `requirements.lock`
(full pinned closure), and [.github/workflows/ci.yml](.github/workflows/ci.yml) running
ruff → mypy → pytest on Python 3.10–3.12. Fixed every issue the tools surfaced — including
two real ones: a `raise None` path in the NVD retry loop and a `top` variable reused as both
a list and a str in the report.
**Done when — met.** Lint, type-check, and tests are all green locally; CI enforces them.

### 9. Deepen the tests beyond smoke checks — DONE
**Problem.** Tests were mostly structural; few pinned values; the Table I-2 matrix had ~4
of 25 cells checked.
**What was done.** Added: a full **Table I-2** test (all 25 cells, against an independently
written expected matrix), **value-pinning** for likelihood/impact on a deterministic line
graph (hand-computed 70.0 / 58.0 / 49.6 etc.), and **property tests** (likelihood monotonic
in exposure; authentication never raises likelihood). The earlier sensitivity test already
guards ranking stability.
**Done when — met.** A scoring-weight or matrix change now breaks a specific test; 37 tests
pass.

---

**Tier 3 complete.** The project is an installable package with a console entry point,
CI-enforced lint/type/test gates on three Python versions, a pinned lockfile, and tests that
pin real values rather than just smoke-checking structure.

---

## Tier 4 — Security credibility

Standard artifacts, framework alignment, and self-applied security hygiene that signal a
real cyber project rather than a Python project about security.

### 10. ATT&CK Navigator layer export — DONE
**Why.** Analysts work in MITRE's ATT&CK Navigator daily; a Navigator-compatible layer is an
instantly recognizable artifact and reuses the technique mapping already built.
**What was done.** `frameworks.navigator_layer` / `write_navigator_layer` emit a valid
`domain: "ics-attack"` layer — one entry per exposed technique, scored by the number of
assets exposing it, with the asset names in the comment and a heat gradient. The pipeline
writes `attack_navigator_layer.json` alongside the briefing; the committed sample is in
`examples/water_treatment/`. Tests validate the layer structure.
**Done when — met.** The pipeline emits a `.json` that loads in ATT&CK Navigator and
highlights the architecture's exposed techniques.

### 11. IEC 62443 zones & conduits alignment — DONE
**Why.** IEC 62443 is the ICS-specific security standard; the Purdue + segmentation model is
already a zones-and-conduits model, so making it explicit is high ICS credibility.
**What was done.** `frameworks.IEC_62443_ZONE` maps each Purdue level to a 62443 security
zone; the briefing gained an "IEC 62443 zones & conduits" section that groups assets by zone,
flags any IT→OT conduit that bypasses the Industrial DMZ (reusing `segmentation_violations`),
and cites IEC 62443-3-3.
**Done when — met.** The briefing presents the architecture in 62443 zone/conduit terms and
cites the standard.

### 12. Supply-chain security + SECURITY.md — DONE
**Why.** A security project is judged on its own hygiene; scanning its dependencies and
publishing a disclosure policy is table stakes.
**What was done.** Added a `pip-audit` job to CI that audits `requirements.lock` (it caught
a real one — pytest CVE-2025-71176, now pinned to ≥9.0.3), pinned the GitHub Actions by
commit SHA, set `permissions: contents: read`, added `.github/dependabot.yml` (pip +
github-actions), and a `SECURITY.md` (supported versions, private disclosure, supply-chain
notes).
**Done when — met.** CI fails on a known-vulnerable dependency; `SECURITY.md` exists; the
lockfile audits clean.

### 13. ATT&CK mitigations mapping — DONE
**Why.** Mapping weaknesses to techniques says what's exposed; mapping techniques to their
ATT&CK mitigations turns that into cited countermeasures — what a real assessment delivers.
**What was done.** `data_sources.load_attack_mitigations` joins ATT&CK course-of-action
(mitigation) objects to techniques via `mitigates` relationships. The briefing gained an
"ATT&CK-grounded mitigations" section pairing each exposed technique with its ATT&CK for ICS
M-codes (e.g. M0930 Network Segmentation, M0807 Network Allowlists), ranked by coverage.
**Done when — met.** Briefing recommendations cite specific ATT&CK mitigations per exposed
technique.

### 20. EPSS exploitation scoring — DONE
**Why.** KEV is a binary, lagging signal (a CVE is on the list only after exploitation is
confirmed). FIRST.org's EPSS is a published ML model that predicts 30-day exploitation
probability, which is exactly the forward-looking signal the risk model lacked.
**What was done.** `data_sources.fetch_epss` batch-queries the EPSS API and caches it; the
snapshot builder attaches an EPSS probability + percentile to every CVE and ranks CVEs by it.
The exploitation escalator now fires on KEV *or* top-percentile EPSS (≥ 0.95), and the
briefing shows EPSS per CVE plus an EPSS line in the provenance stamp. EPSS scores are
right-skewed, so the percentile is the threshold. On the water plant EPSS escalates three
assets that KEV alone does not, so the signals are complementary, not redundant. This is the
"incorporate ML efficiently" path: consume a published model's output as a feature, leaving
the engine deterministic and auditable.

---

**Tier 4 complete.** The project now ships recognizable analyst artifacts (ATT&CK Navigator
layer), aligns to the ICS standard (IEC 62443 zones/conduits), practices its own supply-chain
security (pip-audit, SHA-pinned actions, Dependabot, SECURITY.md), and grounds its
recommendations in ATT&CK mitigations.

---

## Tier 5 — Research rigor

### 14. Validity experiment — DONE
**Why.** The model produced scores and rankings with no evidence they are *correct*; the
sensitivity analysis tested robustness, not validity. A reviewer's first question is "does the
machinery beat a trivial heuristic, and which factors actually matter?"
**What was done.** Added `experiments/validity.py` (+ reproducible
[experiments/RESULTS.md](experiments/RESULTS.md)) with a from-scratch Kendall's τ-b instrument
(itself unit-tested). It runs an **ablation** (drop each scoring factor, measure ranking
change), a **discriminant** check (vs a Purdue-criticality-only baseline), a **convergent**
check (vs betweenness / entry-distance / CVE-severity lenses), and a **face-validity** check
on the Oldsmar pattern.
**Findings (honest).** The ranking tracks the trivial criticality baseline at τ-b ≈ 0.7 with
an identical top-3 — process criticality does most of the work; **authentication** is the most
influential likelihood factor; the **KEV/CVE signal is sparse and nearly inert for ranking**;
convergent agreement with independent lenses is weak; criterion validity is untested.
### 15. Incident reconstruction check (NOT criterion validity) — DONE, relabeled
**Correction.** This was originally framed as criterion validity, which a code review correctly
called circular: the architecture is reconstructed by the same author who then declares the
expected path, so the expected waypoints *are* the nodes encoded in the graph. Recovering them
confirms the modeling and path-finding layers work on a documented incident — an integration /
reachability check — not that the tool *predicts* attacks. Relabeled accordingly in the script,
`CRITERION_RESULTS.md`, and the README.
**What it does show.** The **2015 Ukraine power-grid attack** (E-ISAC/SANS; ICS-CERT
IR-ALERT-H-16-056-01), reconstructed in `experiments/ukraine_2015.yaml`, is expressible in the
schema, and the unchanged tool surfaces its root cause, path, and OT techniques without any
special-casing. Useful, but integration-level evidence.
**Still open.** True predictive / criterion validity needs a **blind** architecture authored by
someone other than the tool author. Cannot be closed solo.

### 16. Version-aware CVE matching + provenance stamps — DONE
**Why.** CVEs were matched at product level (version dropped), so old CVEs got attached to
patched/newer assets — false precision; and briefings carried no data provenance.
**What was done.** `lookup_cves_by_cpe` now checks each CVE's NVD version ranges against the
asset's version: confirmed-not-affected CVEs are dropped, the rest carry a `version_status`
(`confirmed` / `unconfirmed`) shown in the briefing as *(version not confirmed)*. The snapshot
gained a `_meta` block (generation date, KEV catalog date/count), and every briefing ends with
a provenance line (ATT&CK source + fetch date, KEV date/count, snapshot date). Effect: e.g.
old AVEVA InTouch and S7-1500 CVEs that don't apply to the modeled versions are now dropped.

### 18. Ablation follow-ups: act on the inert factor + ablate segmentation — DONE
**Why.** The validity ablation left two threads: it never ablated segmentation, and it found
the CVE/KEV factor inert without acting on it.
**What was done.** `experiments/ablation_followup.py` (+ `ABLATION_FOLLOWUP.md`) measured both.
(a) **Segmentation** excludes **0** attack paths on either reference plant — its real
contribution is bypass detection, not path filtering (the exclusion capability is genuine and
unit-tested but doesn't fire here). (b) The **KEV factor** changed no band/rank even for the
asset that carried a KEV CVE, so it was **removed as a likelihood weight and re-applied as a
band escalator** (actively-exploited → +1 band, CISA BOD 22-01) — now decision-relevant
(water's `dosing_plc` goes High → Very High). Sensitivity was re-checked: priority
ranking stays robust (top-1 100%, top-3 89%), per-asset bands are more weight-sensitive (~75%)
since the removed factor was an inert variance-dampener. Rubric, README, and tests updated.

### 17. Prior-art positioning — DONE
**Why.** The repo reinvented attack-graph analysis without saying so; a reviewer's first
question is "what's new vs. MulVAL et al.?"
**What was done.** Added a "Related work and contribution" section to the README positioning
against the attack-graph literature and commercial ICS platforms, with the honest claim: the
contribution is **integration** (ATT&CK-ICS + 62443 + 800-30 + CVE/KEV + segmentation +
briefing/Navigator export), not a novel algorithm.

### 19. Realistic-scale architecture + scaling analysis — DONE
**Why.** Everything had been validated on ~10–14 node hand-authored models; no evidence the
algorithms or narrative survive at realistic scale.
**What was done.** `experiments/scale.py` generates a synthetic hierarchical plant (site SCADA
over N areas, each with controllers + field devices) at 94 → 1,106 nodes and times every stage
([experiments/SCALE.md](experiments/SCALE.md)). **Findings:** per-run analysis (graph, mapping,
attack paths, scoring, segmentation) stays in the low tens of milliseconds even at ~1,100
nodes; the bottlenecks are **betweenness centrality** (O(V·E), ~2 s at 1,106 nodes) and
**`sensitivity()`** (re-scores ~81×, skipped above a few hundred nodes), both with known local
fixes (sample-approximate betweenness; memoize graph-derived factors). Figures stop being
*visually* useful past ~50 nodes — the text/table/Navigator outputs are what scale. A smoke
test guards the generator.

**Still open.** A *blind* criterion test — an architecture authored by someone other than the
tool author, to remove residual modeling bias. Needs a second person, so it can't be closed
solo; surfaced deliberately rather than hidden.

---

## Explicitly out of scope (for now)

- Live network/traffic analysis — this is a static, model-based tool by design.
- Real-asset/config ingestion — input is a hand-authored model, not a discovered network.
- Automated remediation — recommendations are advisory.

Stating these is deliberate: the tool's value depends on being clear about what it does
*not* claim to do.
