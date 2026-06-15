# Incident-Reconstruction Check — 2015 Ukraine Power Grid

_Source: E-ISAC/SANS, 'Analysis of the Cyber Attack on the Ukrainian Power Grid' (2016); ICS-CERT IR-ALERT-H-16-056-01._

> **This is not criterion validity.** The architecture ([experiments/ukraine_2015.yaml](ukraine_2015.yaml)) is reconstructed by the same author who declares the expected path, so the expected waypoints are the nodes encoded in the graph. This is an **integration / reachability check** — it shows a real documented attack is *expressible and traversable* by the unchanged tool, not that the tool *predicts* attacks. A predictive test needs a blind architecture (see ROADMAP).

## Results

- **Root cause flagged:** YES — the documented root cause was a VPN from business IT into the ICS network without MFA (`vpn_gateway -> scada_dms_server`); the tool flags it as an IT->OT segmentation bypass.
- **Attack-path recovery:** 100% of documented waypoints, in order.
    - documented: `corporate_workstation -> vpn_gateway -> scada_dms_server -> substation_rtu -> breaker`
    - tool's best path: `corporate_workstation -> vpn_gateway -> scada_dms_server -> substation_rtu -> breaker`
- **Critical-asset recall@5:** 80% — 4 of the 5 documented-compromised assets are in the tool's top-5 risk ranking.
    - documented: scada_dms_server, operator_hmi, substation_rtu, serial_ethernet_converter, breaker
    - tool top-5: substation_rtu, serial_ethernet_converter, breaker, scada_dms_server, historian
- **Technique recall (OT, mappable):** 100% — where the tool placed each documented technique:
    - T0822: vpn_gateway
    - T0886: vpn_gateway, substation_rtu, serial_ethernet_converter
    - T1692.001: scada_dms_server, operator_hmi, substation_rtu, serial_ethernet_converter, breaker

## What the tool cannot capture (out of scope, not misses)

The tool models OT exposure, so it does not represent the documented IT-stage and destructive techniques: T0865 Spearphishing, T0859 Valid Accounts, T0857 System Firmware, T0809 Data Destruction. This check covers only the OT attack-surface portion of the incident.

## Reading

- **What it shows:** a real, externally-documented attack is representable in the schema, and the unchanged tool surfaces its root cause, path, and OT techniques — nothing was special-cased for it.
- **What it does NOT show:** predictive validity. The expected waypoints are the nodes the author wired in, so 'recovers them in order' is close to confirming the path-finding layer works. That is useful as an integration test, not as evidence the tool predicts real attacks.
- **Caveat on asset recall:** with ~10 assets and the ranking driven mostly by Purdue criticality (see RESULTS.md), recall@5 mostly confirms the 5 OT assets outrank the 5 IT ones — weakly discriminating. Path recovery and the root-cause flag are stronger.