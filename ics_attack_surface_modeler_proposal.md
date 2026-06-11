# Project Proposal: Cyber-Physical Attack Surface Modeler
**Threat modeling and vulnerability prioritization for ICS/SCADA reference architectures**

---

## Objective

Build a framework that models the attack surface of an industrial control system (ICS/SCADA), maps components to known adversary techniques via MITRE ATT&CK for ICS, scores and prioritizes vulnerabilities, and generates a structured vulnerability briefing. The goal is to demonstrate cyber-physical threat-modeling skill and security-framework fluency on public reference architectures — original work, no proprietary content.

Maps to the resume bullet: *"Assessed cyber-physical attack surfaces across the Northeast Corridor… and delivered a briefing and vulnerability report pairing infrastructure posture with emerging infrastructure-cyberattack trends."* This project demonstrates the same skills (attack-surface analysis, vulnerability reporting, threat-trend mapping) on public ICS reference systems.

---

## Scope

- **Reference systems:** public ICS/SCADA reference architectures. Good anchors:
  - The Purdue Enterprise Reference Architecture (Purdue Model) — the standard layered ICS model
  - A rail / transit signaling reference architecture (CENELEC / FRA public docs) to keep it thematically close to the real work
  - A water treatment or power-grid reference (e.g. the EPA/CISA water sector reference) as an alternative
- **Adversary framework:** MITRE ATT&CK for ICS (public matrix of tactics and techniques)
- **Vulnerability data:** CISA ICS advisories and the CVE database (both public APIs / downloadable)

---

## Threat Model

The adversary is modeled by **starting position and goal**, not by modeling actor sophistication in detail. ICS threat actors are predominantly nation-state class (cf. Stuxnet, TRITON/TRISIS, Industroyer); we capture that as a *capability assumption* rather than a modeled entity, which keeps the framework tractable.

- **Capability assumption:** a capable external actor (nation-state class) — can chain multiple techniques, will preferentially use known-exploited CVEs (CISA KEV), and is patient (justifies a generous attack-path cutoff).
- **Adversary profiles (entry-node sets):**
  - *External actor* — enters at L4/L5 (internet / enterprise IT), goal = reach L0/L1 and disrupt the physical process. Primary case; drives the attack-path analysis.
  - *Insider / vendor-maintenance* — enters mid-stack (L3, or via a maintenance laptop / vendor remote-access path), same goal. One additional entry-node set, not a separate framework.

Entry nodes and target (critical) nodes are first-class, declared in the architecture data file — not hardcoded. The briefing states the modeled adversary explicitly, e.g. *"Adversary modeled: capable external actor (nation-state class) entering at the IT/OT boundary."*

---

## Architecture

Four layers: **asset model**, **technique mapping**, **scoring**, **reporting**.

### 1. Asset Model (`assets/`)

Represent the reference architecture as a structured graph of components, zones, and connections.

```python
from dataclasses import dataclass, field
from enum import Enum

class PurdueLevel(Enum):
    L0_PROCESS = 0       # sensors, actuators
    L1_CONTROL = 10      # PLCs, RTUs
    L2_SUPERVISORY = 20  # HMIs, SCADA servers
    L3_OPERATIONS = 30   # historians, MES
    L3_5_DMZ = 35        # IT/OT DMZ — the critical attack-path chokepoint
    L4_ENTERPRISE = 40   # corporate IT
    L5_INTERNET = 50

@dataclass
class Asset:
    name: str
    level: PurdueLevel
    component_type: str         # "PLC", "HMI", "historian", etc.
    # Concrete product identity, so real CVEs can be attached via CPE (see §2).
    vendor: str = ""            # e.g. "Schneider Electric"
    product: str = ""           # e.g. "Modicon M340"
    version: str = ""           # e.g. "3.20"
    protocols: list = field(default_factory=list)   # Modbus, DNP3, etc.
    authenticated: bool = False                      # protocol-level auth present?
    exposed_interfaces: list = field(default_factory=list)
    connections: list = field(default_factory=list)  # names of connected assets
```

Encode the reference architecture as a JSON/YAML file the framework loads. Build the asset graph from it. The graph structure enables attack-path analysis later.

**Decisions baked in:**
- The DMZ (L3.5) is modeled explicitly — it's the single most important zone for attack-path realism.
- Assets name **concrete commercial products** (vendor/product/version) so the NVD/CVE lookup actually fires (§2). The architecture is a *plausible hypothetical plant* built from widely-documented public products — non-proprietary.
- `connections` are validated on load: every referenced asset name must resolve, or loading fails (no silent disconnected graphs). Entry-node and target-node sets are declared in the same file.

### 2. Technique Mapping (`mapping/`)

Map each asset to the MITRE ATT&CK for ICS techniques it's susceptible to, based on component type, protocols, and exposed interfaces.

- Download the ATT&CK for ICS matrix (available as STIX/JSON from MITRE)
- The mapping logic lives in a **data-driven rules file** (`data/mapping_rules.yaml`), not Python. This makes the mappings auditable by a security reviewer without reading code, carries a `rationale` per rule that flows into the briefing as justification, and reuses the same "framework generalizes" argument as the architecture file.

```yaml
# data/mapping_rules.yaml — conditions are AND-of-fields (covers ~90% of real rules)
rules:
  - id: modbus-unauth-command
    when:
      protocols: [Modbus]      # asset speaks Modbus...
      authenticated: false      # ...with no protocol auth
    techniques: [T0855, T0821, T0836]   # Unauth Command, Modify Controller Tasking, Modify Parameter
    rationale: "Modbus has no native authentication; any L2-reachable host can issue function codes."
  - id: plc-network-exposed
    when:
      component_type: PLC
      exposed_interfaces: [network]
    techniques: [T0886, T0809]
    rationale: "Network-exposed PLC permits remote service access and data-from-information-repository collection."
```

```python
def map_asset_to_techniques(asset, rules, vuln_db):
    """Return ATT&CK techniques (with rationale) and known CVEs applicable to an asset."""
    techniques = [r for r in rules if rule_matches(asset, r["when"])]   # AND-of-fields match
    cves = lookup_cves_by_cpe(asset.vendor, asset.product, asset.version, vuln_db)
    return techniques, cves
```

**CVE matching is CPE-based.** NVD is keyed by CPE (vendor:product:version), not by "PLC" or "Modbus" — so concrete product identity on each asset (§1) is what makes the lookup return real CVEs. Build the CPE string from the asset's vendor/product/version, query NVD, and cache per-product results to disk (NVD's `cpe_match` / version-range semantics are fiddly; refresh deliberately). This is also what makes the CISA-KEV cross-reference fire — the strongest prioritization signal.

### 3. Scoring & Prioritization (`scoring.py`)

Score each asset/technique pairing on likelihood × impact, and run attack-path analysis on the graph. Scoring follows the **NIST SP 800-30 Rev. 1** risk model (`Risk = Likelihood × Impact`, the risk-assessment companion to the SP 800-82 OT guide already cited). Every score is traceable to a documented, cited rubric — not invented. The rubric is a table in the README (`data/risk_rubric.md`).

**Scale:** scored **0–100 internally** (semi-quantitative, per 800-30 Table H-3 — sortable, feeds the risk-matrix scatter), presented as **qualitative bands** (Very Low → Very High) in the briefing.

- **Likelihood factors** (800-30 folds likelihood-of-initiation × likelihood-of-adverse-impact):
  - Exposure: attack-path distance from an entry node / Purdue depth — closer to the IT/OT boundary = higher
  - Protocol authentication: unauthenticated = higher
  - Known-exploited: CVE present in CISA KEV = largest bump (800-30's vulnerability-severity factor)
- **Impact factors** (800-30 Appendix H — harm to operations/assets):
  - Process criticality: does the asset directly affect the physical process / safety
  - Blast radius: count of downstream-dependent assets (from the graph)
- Use CVSS scores where CVEs are attached.

**Attack-path analysis** uses **k-shortest paths** (not full simple-path enumeration, which is combinatorial even at a length cap). Pair with **betweenness centrality** to surface chokepoints — assets sitting on many critical paths — directly as a briefing finding ("Asset X is the most common waypoint to critical assets").

```python
def attack_paths(graph, entry_nodes, target_nodes, k=5):
    """k shortest paths from each external entry point to each critical asset."""
    import networkx as nx
    from itertools import islice
    paths = []
    for entry in entry_nodes:
        for target in target_nodes:
            try:
                ksp = islice(nx.shortest_simple_paths(graph, entry, target), k)
                paths.extend(ksp)
            except nx.NetworkXNoPath:
                continue
    return sorted(paths, key=len)  # shortest = highest priority

def chokepoints(graph):
    """Assets most often on critical paths — high-priority hardening targets."""
    import networkx as nx
    return nx.betweenness_centrality(graph)
```

### 4. Threat-Trend Layer

Mirror the "emerging infrastructure-cyberattack trends" part of the real deliverable: maintain a curated reference of recent ICS attack campaigns (e.g. public write-ups of attacks on water, energy, transit) and map them to the techniques in your matrix. The report then connects the architecture's specific weaknesses to real-world attack patterns that have been observed in the wild.

### 5. Report Generator (`report.py`)

Produce a structured vulnerability briefing:
- Executive summary (highest-priority findings, most exposed critical assets)
- Asset inventory by Purdue level
- Technique exposure matrix (asset × ATT&CK technique)
- Attack-path findings (shortest paths to critical assets, ranked)
- Known-CVE summary with CVSS scores
- Threat-trend mapping (which real-world campaigns this architecture is vulnerable to)
- Prioritized mitigation recommendations

This report is the deliverable that mirrors the real briefing.

---

## Plots / Visualizations

- **Network diagram** of the asset graph, colored by Purdue level and sized by criticality (use `networkx` + `matplotlib` or export to Graphviz)
- **Technique exposure heatmap** (asset × technique)
- **Attack-path diagram** highlighting the shortest external-to-critical paths
- **Risk matrix** (likelihood × impact scatter, one point per finding)

---

## Repository Structure

```
ics_attack_surfaces/
├── README.md
├── requirements.txt
├── data/
│   ├── reference_architecture.yaml   # The modeled ICS system (assets + entry/target nodes)
│   ├── mapping_rules.yaml            # Data-driven asset → technique rules (auditable)
│   ├── attack_ics.json               # MITRE ATT&CK for ICS (downloaded)
│   ├── threat_trends.yaml            # Curated recent campaign references
│   ├── risk_rubric.md                # NIST 800-30 scoring rubric (cited, reproducible)
│   └── README.md                     # Data sources and how to refresh them
├── src/
│   ├── assets.py                     # Asset model + graph construction
│   ├── mapping.py                    # Asset → technique/CVE mapping
│   ├── scoring.py                    # Likelihood/impact + attack paths
│   ├── trends.py                     # Threat-trend mapping
│   ├── report.py                     # Briefing + plot generation
│   └── data_sources.py               # CISA advisory / CVE / KEV fetchers
├── results/
│   ├── figures/
│   └── briefing.md                   # Generated vulnerability briefing
└── notebooks/
    └── demo.ipynb
```

---

## Dependencies

Pin version bounds for reproducibility:

```
networkx>=3.2,<4
pyyaml>=6.0,<7
requests>=2.31,<3      # CISA / NVD API access
pandas>=2.1,<3
matplotlib>=3.8,<4
graphviz>=0.20,<1      # optional, for nicer network diagrams
```

---

## Implementation Order

1. Choose and encode one reference architecture as `reference_architecture.yaml` — concrete commercial products (vendor/product/version), explicit DMZ (L3.5), and declared entry-node / target-node sets. Validate connections resolve on load.
2. Build the asset model and construct the graph; render the network diagram to verify structure
3. Download MITRE ATT&CK for ICS (STIX/JSON); parse into a usable technique list
4. Author `mapping_rules.yaml` (data-driven, AND-of-fields conditions, `rationale` per rule) and the ~30-line rule engine
5. Wire up CISA advisory / NVD CVE lookups **by CPE**; cache per-product results to disk; attach CVEs to assets; cross-reference CISA KEV
6. Implement likelihood/impact scoring per the NIST 800-30 rubric (0–100 internal, bands in briefing); write `risk_rubric.md`
7. Implement attack-path analysis (k-shortest paths) + betweenness-centrality chokepoint scoring
8. Build the threat-trend reference and mapping
9. Build the report generator and all visualizations
10. Write README + a few unit tests (rule matching, YAML schema validation); verify the briefing regenerates end-to-end

---

## Notes for Claude Code

- The MITRE ATT&CK for ICS data is available as STIX 2.0 JSON from the official MITRE CTI GitHub repo — parse with the `mitreattack-python` library or directly
- The NVD CVE API is rate-limited without an API key; cache responses to disk and document the refresh process
- The CISA Known Exploited Vulnerabilities (KEV) catalog is a single downloadable JSON — use it to flag CVEs that are actively exploited (a strong prioritization signal)
- Keep the reference architecture in a data file, not hardcoded — the whole point is that the framework generalizes to any ICS you describe
- The threat-trend references should be a curated, cited data file (real public campaign write-ups), not generated — accuracy matters here and fabricated campaigns would undermine the project
- Attack-path enumeration can explode on large graphs; cap path length (cutoff=6 is reasonable) and document it

---

## References

- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- CISA ICS Advisories: https://www.cisa.gov/news-events/cybersecurity-advisories
- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD CVE API: https://nvd.nist.gov/developers/vulnerabilities
- Purdue Enterprise Reference Architecture (Purdue Model) — standard ICS network segmentation reference
- Stouffer, K., et al. *NIST SP 800-82 Rev. 3: Guide to Operational Technology (OT) Security.* https://csrc.nist.gov/pubs/sp/800/82/r3/final
