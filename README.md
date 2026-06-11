# Cyber-Physical Attack Surface Modeler

Threat modeling and vulnerability prioritization for ICS/SCADA reference architectures.

Models the attack surface of an industrial control system, maps components to MITRE
ATT&CK for ICS techniques, scores and prioritizes risk (NIST SP 800-30), and generates
a structured vulnerability briefing. Built entirely on **public reference architectures
and public data** — no proprietary content.

See [`ics_attack_surface_modeler_proposal.md`](ics_attack_surface_modeler_proposal.md)
for the full design.

## Status

End-to-end functional. The pipeline loads the reference architecture, maps assets to
ATT&CK for ICS techniques, scores risk (NIST 800-30 Table I-2), runs **segmentation-aware**
attack-path / chokepoint analysis (paths respect the firewall policy; IT→OT boundary
bypasses are flagged), correlates real campaigns, and generates the briefing + figures.
CVE/KEV enrichment is opt-in (`--cves`, requires network).

## Layout

```
data/    Reference architecture, mapping rules, threat trends, scoring rubric (all data, cited)
ics_modeler/ assets · mapping · scoring · trends · report · data_sources
tests/   Unit tests (rule matching, schema validation)
results/ Generated briefing + figures
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"                        # installs the package + dev tooling
#   (or: pip install -r requirements.lock      # exact pinned versions)
pytest                                          # run the tests
ics-modeler                                     # transit-signaling model (default)
ics-modeler --arch data/water_treatment.yaml --out results_water   # water-treatment model
ics-modeler --cves                              # ...with live NVD CVE + CISA KEV enrichment
```

`ics-modeler` is the installed console command; `python -m ics_modeler.pipeline` is
equivalent if you'd rather not install.

## Development

```bash
ruff check ics_modeler scripts tests    # lint
mypy ics_modeler                         # type-check
pytest                                   # tests
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all three on Python
3.10–3.12 for every push and PR.

Two reference architectures ship with the project — a transit-signaling plant
([data/reference_architecture.yaml](data/reference_architecture.yaml)) and a municipal
water-treatment plant ([data/water_treatment.yaml](data/water_treatment.yaml), different
vendors and protocols) — to demonstrate the framework generalizes.

## Pipeline (target)

1. Load + validate `reference_architecture.yaml` → asset graph
2. Map assets → ATT&CK techniques via `mapping_rules.yaml`
3. Attach real CVEs via NVD (CPE lookup) + flag CISA KEV
4. Score likelihood × impact (NIST 800-30) + attack-path / chokepoint analysis
5. Map to recent real-world campaigns (`threat_trends.yaml`)
6. Generate the briefing + figures into `results/`

## Data sources

See [`data/README.md`](data/README.md) for sources and refresh instructions.
