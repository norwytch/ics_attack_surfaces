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
ATT&CK for ICS techniques, scores risk (NIST 800-30 Table I-2), runs attack-path /
chokepoint analysis, correlates real campaigns, and generates the briefing + figures.
CVE/KEV enrichment is opt-in (`--cves`, requires network).

## Layout

```
data/    Reference architecture, mapping rules, threat trends, scoring rubric (all data, cited)
src/     assets · mapping · scoring · trends · report · data_sources
tests/   Unit tests (rule matching, schema validation)
results/ Generated briefing + figures
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/                      # run the tests
python -m src.pipeline                        # generate results/briefing.md + figures (offline)
python -m src.pipeline --cves                 # ...with live NVD CVE + CISA KEV enrichment
```

## Pipeline (target)

1. Load + validate `reference_architecture.yaml` → asset graph
2. Map assets → ATT&CK techniques via `mapping_rules.yaml`
3. Attach real CVEs via NVD (CPE lookup) + flag CISA KEV
4. Score likelihood × impact (NIST 800-30) + attack-path / chokepoint analysis
5. Map to recent real-world campaigns (`threat_trends.yaml`)
6. Generate the briefing + figures into `results/`

## Data sources

See [`data/README.md`](data/README.md) for sources and refresh instructions.
