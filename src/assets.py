"""Asset model + graph construction.

Loads a reference architecture from YAML, validates it, and builds a networkx graph.
This module is functional; the rest of the pipeline builds on the graph it produces.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import yaml


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
    component_type: str
    vendor: str = ""
    product: str = ""
    version: str = ""
    protocols: list = field(default_factory=list)
    authenticated: bool = False
    exposed_interfaces: list = field(default_factory=list)
    connections: list = field(default_factory=list)  # names of connected assets

    def cpe_hint(self) -> str | None:
        """Rough CPE-ish identifier for NVD lookup; None if product unknown."""
        if not (self.vendor and self.product):
            return None
        return f"{self.vendor}:{self.product}:{self.version}".strip(":")


@dataclass
class Architecture:
    assets: dict          # name -> Asset
    entry_nodes: list     # asset names where the adversary starts
    target_nodes: list    # critical asset names
    meta: dict = field(default_factory=dict)

    def graph(self):
        """Build an undirected networkx graph of the architecture."""
        import networkx as nx

        g = nx.Graph()
        for asset in self.assets.values():
            g.add_node(asset.name, asset=asset, level=asset.level.name)
        for asset in self.assets.values():
            for other in asset.connections:
                g.add_edge(asset.name, other)
        return g


def load_architecture(path: str) -> Architecture:
    """Load and validate a reference architecture YAML into an Architecture.

    Validation: every connection / entry / target name must resolve to a declared
    asset, or loading fails — no silent disconnected graphs.
    """
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    assets: dict = {}
    for item in raw.get("assets", []):
        try:
            level = PurdueLevel[item["level"]]
        except KeyError as e:
            raise ValueError(f"Asset {item.get('name')!r}: bad/missing level {e}") from e
        # A float version (unquoted `3.20` in YAML) silently truncates to `3.2`,
        # producing a wrong CPE. Force the author to quote it.
        if isinstance(item.get("version"), float):
            raise ValueError(
                f"Asset {item.get('name')!r}: version must be quoted in YAML "
                f"(got float {item['version']!r}; e.g. write version: \"3.20\")"
            )
        asset = Asset(
            name=item["name"],
            level=level,
            component_type=item.get("component_type", ""),
            vendor=item.get("vendor", ""),
            product=item.get("product", ""),
            version=str(item.get("version", "")),
            protocols=item.get("protocols", []),
            authenticated=bool(item.get("authenticated", False)),
            exposed_interfaces=item.get("exposed_interfaces", []),
            connections=item.get("connections", []),
        )
        if asset.name in assets:
            raise ValueError(f"Duplicate asset name: {asset.name!r}")
        assets[asset.name] = asset

    _validate_references(assets, raw.get("entry_nodes", []), raw.get("target_nodes", []))

    return Architecture(
        assets=assets,
        entry_nodes=raw.get("entry_nodes", []),
        target_nodes=raw.get("target_nodes", []),
        meta=raw.get("meta", {}),
    )


def _validate_references(assets: dict, entry_nodes: list, target_nodes: list) -> None:
    names = set(assets)
    for asset in assets.values():
        for conn in asset.connections:
            if conn not in names:
                raise ValueError(
                    f"Asset {asset.name!r} connects to unknown asset {conn!r}"
                )
    for label, group in (("entry_nodes", entry_nodes), ("target_nodes", target_nodes)):
        for n in group:
            if n not in names:
                raise ValueError(f"{label} references unknown asset {n!r}")


if __name__ == "__main__":
    arch = load_architecture("data/reference_architecture.yaml")
    g = arch.graph()
    print(f"Loaded {len(arch.assets)} assets, {g.number_of_edges()} connections.")
    print(f"Entry nodes:  {arch.entry_nodes}")
    print(f"Target nodes: {arch.target_nodes}")
