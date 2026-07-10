"""Transitive resolution — attach the attack path(s) to each vulnerability finding."""
from __future__ import annotations

import networkx as nx

from ..graph.builder import lib_node
from ..graph.traversal import count_paths, shortest_attack_path
from ..models import Finding


def annotate_paths(g: nx.DiGraph, findings: list[Finding]) -> None:
    for f in findings:
        if f.risk_type not in ("vulnerable", "transitive_vuln"):
            continue
        target = lib_node(f.app_id, f.library, f.version)
        path = shortest_attack_path(g, f.app_id, target)
        f.paths = [path] if path else []
        if not f.is_direct:
            n = count_paths(g, f.app_id, target)
            extra = f" via {len(path)}-hop chain" if path else ""
            more = f" ({n} paths)" if n > 1 else ""
            f.detail = f"{f.detail} Transitive{extra}{more}."
