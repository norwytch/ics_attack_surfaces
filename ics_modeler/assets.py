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


def _hop_weight(dst: Asset) -> float:
    """Difficulty of taking `dst` as the next hop — unauthenticated targets are easier."""
    return 1.0 if not dst.authenticated else 2.0


@dataclass
class Segmentation:
    """Zone-to-zone traversal policy. Zones are Purdue level names.

    A transition between assets in different zones is checked against any matching
    boundary (an unordered zone pair). If a boundary matches, the destination must speak
    a protocol in that boundary's allow-list (empty allow-list = blocked). Transitions
    with no matching boundary follow `default_allow`; same-zone traffic is always allowed.

    An empty policy (no boundaries, default_allow=True) reproduces full physical
    reachability, so architectures with no `segmentation:` section behave as before.
    """
    default_allow: bool = True
    boundaries: list = field(default_factory=list)  # [{"zones": frozenset, "allow": set}]

    def permits(self, src: Asset, dst: Asset) -> bool:
        if src.level.name == dst.level.name:
            return True
        for b in self.boundaries:
            if b["zones"] == frozenset({src.level.name, dst.level.name}):
                return bool(b["allow"] & set(dst.protocols))
        return self.default_allow


@dataclass
class Architecture:
    assets: dict          # name -> Asset
    entry_nodes: list     # asset names where the adversary starts
    target_nodes: list    # critical asset names
    meta: dict = field(default_factory=dict)
    segmentation: Segmentation = field(default_factory=Segmentation)

    def graph(self):
        """Build an undirected networkx graph of the physical topology.

        Used for the network diagram and centrality. For attacker reachability use
        `reachability_graph()`, which respects the segmentation policy.
        """
        import networkx as nx

        g = nx.Graph()
        for asset in self.assets.values():
            g.add_node(asset.name, asset=asset, level=asset.level.name)
        for asset in self.assets.values():
            for other in asset.connections:
                g.add_edge(asset.name, other)
        return g

    def reachability_graph(self):
        """Directed graph of attacker-traversable edges under the segmentation policy.

        Each physical connection yields a directed edge in whichever direction(s) the
        policy permits, weighted by hop difficulty. This is the graph attack-path
        analysis should run on — edges the policy denies simply do not exist here.
        """
        import networkx as nx

        g = nx.DiGraph()
        for asset in self.assets.values():
            g.add_node(asset.name, asset=asset, level=asset.level.name)
        for asset in self.assets.values():
            for other in asset.connections:
                dst = self.assets[other]
                if self.segmentation.permits(asset, dst):
                    g.add_edge(asset.name, dst.name, weight=_hop_weight(dst))
                if self.segmentation.permits(dst, asset):
                    g.add_edge(dst.name, asset.name, weight=_hop_weight(asset))
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
        segmentation=_load_segmentation(raw.get("segmentation")),
    )


def _load_segmentation(raw) -> Segmentation:
    """Parse and validate the optional `segmentation:` section."""
    if not raw:
        return Segmentation()
    boundaries = []
    for b in raw.get("boundaries", []):
        zones = b.get("between", [])
        if len(zones) != 2:
            raise ValueError(f"segmentation boundary `between` must list 2 zones: {b}")
        for z in zones:
            if z not in PurdueLevel.__members__:
                raise ValueError(f"segmentation boundary references unknown zone {z!r}")
        boundaries.append({"zones": frozenset(zones),
                           "allow": set(b.get("allow_protocols", []))})
    return Segmentation(default_allow=(raw.get("default", "allow") == "allow"),
                        boundaries=boundaries)


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
