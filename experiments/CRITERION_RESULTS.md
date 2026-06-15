# Criterion-Validity Test — 2015 Ukraine Power Grid

_Ground truth: E-ISAC/SANS, 'Analysis of the Cyber Attack on the Ukrainian Power Grid' (2016); ICS-CERT IR-ALERT-H-16-056-01._

Architecture ([experiments/ukraine_2015.yaml](ukraine_2015.yaml)) reconstructed from public reporting; the tool is run unchanged. Ground truth is the documented attack, defined independently of the tool's output.

## Results

- **Root cause flagged:** YES — the documented root cause was a VPN from business IT into the ICS network without MFA (`vpn_gateway -> scada_dms_server`); the tool flags it as an IT->OT segmentation bypass.
- **Attack-path recovery:** 100% of documented waypoints, in order.
    - documented: `corporate_workstation -> vpn_gateway -> scada_dms_server -> substation_rtu -> breaker`
    - tool's best path: `corporate_workstation -> vpn_gateway -> scada_dms_server -> substation_rtu -> breaker`
- **Critical-asset recall@5:** 100% — 5 of the 5 documented-compromised assets are in the tool's top-5 risk ranking.
    - documented: scada_dms_server, operator_hmi, substation_rtu, serial_ethernet_converter, breaker
    - tool top-5: substation_rtu, scada_dms_server, serial_ethernet_converter, breaker, operator_hmi
- **Technique recall (OT, mappable):** 100% — where the tool placed each documented technique:
    - T0822: vpn_gateway
    - T0886: vpn_gateway, substation_rtu, serial_ethernet_converter
    - T1692.001: scada_dms_server, operator_hmi, substation_rtu, serial_ethernet_converter, breaker

## What the tool cannot capture (out of scope, not misses)

The tool models OT exposure, so it does not represent the documented IT-stage and destructive techniques: T0865 Spearphishing, T0859 Valid Accounts, T0857 System Firmware, T0809 Data Destruction. A criterion-validity claim covers only the OT attack-surface portion of the incident.

## Honest reading

- This is **reconstruction-based** criterion validity: stronger than face validity (a real, independently-documented incident), weaker than a blind test (the architecture is still hand-authored, so modeling bias is possible).
- n=1 incident. Recovering one documented attack is encouraging, not conclusive; it shows the tool's IT->OT-bypass and command-path reasoning aligns with one real case it was not built around.
- **Caveat on asset recall:** with ~10 assets and the ranking driven mostly by Purdue criticality (see RESULTS.md), recall@5 mostly confirms the 5 OT assets outrank the 5 IT ones — weakly discriminating. Path recovery and the root-cause flag are stronger.