"""Reachability engine — mark each vulnerability Exploitable or Present-but-unreachable.

A vulnerable node is Exploitable only if the app reaches it over a path where every
edge is actually used. Unreachable vulns are the false-positive class this suppresses.
"""
from __future__ import annotations

import networkx as nx

from ..graph.builder import lib_node
from ..graph.traversal import used_reachable
from ..models import Finding


def annotate_reachability(g: nx.DiGraph, findings: list[Finding]) -> None:
    cache: dict[str, set[str]] = {}
    for f in findings:
        if f.risk_type not in ("vulnerable", "transitive_vuln"):
            continue
        reach = cache.get(f.app_id)
        if reach is None:
            reach = used_reachable(g, f.app_id)
            cache[f.app_id] = reach
        f.is_reachable = lib_node(f.app_id, f.library, f.version) in reach
        if f.is_reachable is False:
            f.detail = f"{f.detail} Present but UNREACHABLE — no used call path."
