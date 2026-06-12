# Cyber-Physical Attack Surface Modeler

[![CI](https://github.com/norwytch/ics_attack_surfaces/actions/workflows/ci.yml/badge.svg)](https://github.com/norwytch/ics_attack_surfaces/actions/workflows/ci.yml)

Threat modeling and vulnerability prioritization for ICS/SCADA reference architectures.

Models the attack surface of an industrial control system, maps components to MITRE
ATT&CK for ICS techniques, scores and prioritizes risk (NIST SP 800-30), and generates
a structured vulnerability briefing. Built entirely on **public reference architectures
and public data** — no proprietary content.

**What it demonstrates:** cyber-physical threat modeling on the Purdue model and IEC 62443
zones/conduits, fluency with ATT&CK for ICS / NIST SP 800-30 / CISA KEV, segmentation and
attack-path reasoning, an ATT&CK Navigator layer export, and a reproducible data pipeline
over public security sources. Design decisions and trade-offs are recorded in
[ROADMAP.md](ROADMAP.md).

## Status

End-to-end functional. The pipeline loads the reference architecture, maps assets to
ATT&CK for ICS techniques, scores risk (NIST 800-30 Table I-2), runs **segmentation-aware**
attack-path / chokepoint analysis (paths respect the firewall policy; IT→OT boundary
bypasses are flagged), correlates real campaigns, and generates the briefing + figures.
Real CVEs (CPE-matched, KEV-flagged) are attached from a committed snapshot **by default**;
`--cves` refreshes them live from NVD.

## Sample output

A full generated briefing for the water-treatment model is committed at
[`examples/water_treatment/`](examples/water_treatment/briefing.md) — executive summary,
risk-ranked assets, IEC 62443 zones/conduits, IT/OT segmentation findings, ranked attack
paths, CPE-matched CVEs, confidence-scored threat-trend correlation, and ATT&CK-grounded
mitigations (M-codes). It also exports an
[ATT&CK Navigator layer](examples/water_treatment/attack_navigator_layer.json) (load it at
[attack-navigator](https://mitre-attack.github.io/attack-navigator/)). The modeled asset
graph (color = Purdue level, size = impact):

![ICS asset graph](examples/water_treatment/figures/network.png)

## Demo

[`notebooks/demo.ipynb`](notebooks/demo.ipynb) is an **executed** end-to-end walkthrough —
load the model → map ATT&CK techniques → score risk → flag segmentation bypasses → rank
attack paths → stress-test the weights → render the figures. Outputs are saved in the
notebook, so it reads on GitHub without running. To run it yourself:

```bash
pip install -e ".[dev]" jupyter
jupyter notebook notebooks/demo.ipynb
```

## Layout

```
data/        Architectures, mapping rules, threat trends, CVE snapshot, scoring rubric (cited)
ics_modeler/ assets · mapping · scoring · trends · report · data_sources · pipeline
scripts/     One-off data builders (ATT&CK harvest, CVE snapshot)
tests/       Unit tests
examples/    Committed sample briefing + figures
notebooks/   demo.ipynb — executed end-to-end walkthrough
results/     Generated briefing + figures (gitignored)
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"                        # installs the package + dev tooling
#   reproducible: pip install -r requirements.lock && pip install -e . --no-deps
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
3.10–3.12 for every push and PR, plus [`pip-audit`](https://github.com/pypa/pip-audit)
against the lockfile (SHA-pinned actions, Dependabot enabled). See
[SECURITY.md](SECURITY.md) for the disclosure policy.

Two reference architectures ship with the project — a transit-signaling plant
([data/reference_architecture.yaml](data/reference_architecture.yaml)) and a municipal
water-treatment plant ([data/water_treatment.yaml](data/water_treatment.yaml), different
vendors and protocols) — to demonstrate the framework generalizes.

## Pipeline

1. Load + validate the architecture YAML → asset graph + segmentation policy
2. Map assets → ATT&CK for ICS techniques via `mapping_rules.yaml`
3. Attach CPE-matched, KEV-flagged CVEs (committed snapshot by default; `--cves` for live NVD)
4. Score risk (NIST 800-30 Table I-2) + segmentation-aware attack-path / chokepoint analysis
5. Correlate real campaigns (`threat_trends.yaml`) with a confidence score
6. Generate the briefing (incl. IEC 62443 zones/conduits), figures, and an ATT&CK Navigator
   layer into `results/`

## Data sources

See [`data/README.md`](data/README.md) for sources and refresh instructions.
