"""Graph traversal helpers shared by the transitive and reachability engines."""
from __future__ import annotations

import networkx as nx

from .builder import app_node


def used_reachable(g: nx.DiGraph, app_id: str) -> set[str]:
    """Library nodes reachable from the app over edges where used=True.

    This is the reachability rule: a vulnerable node is 'exploitable' only if the
    app actually exercises the whole path to it.
    """
    start = app_node(app_id)
    if not g.has_node(start):
        return set()
    reachable: set[str] = set()
    stack = [start]
    while stack:
        n = stack.pop()
        for _u, v, data in g.out_edges(n, data=True):
            if data.get("used") and v not in reachable:
                reachable.add(v)
                stack.append(v)
    return reachable


def _labels(g: nx.DiGraph, nodes: list[str]) -> list[str]:
    out = []
    for n in nodes:
        d = g.nodes[n]
        if d.get("kind") == "app":
            continue
        out.append(f"{d['library']}@{d['version']}")
    return out


def shortest_attack_path(g: nx.DiGraph, app_id: str, target: str) -> list[str]:
    """Shortest dependency chain app -> ... -> target, as library@version labels."""
    start = app_node(app_id)
    try:
        path = nx.shortest_path(g, start, target)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []
    return _labels(g, path)


def count_paths(g: nx.DiGraph, app_id: str, target: str, cutoff: int = 8) -> int:
    """Number of distinct dependency paths from the app to the target."""
    start = app_node(app_id)
    if not (g.has_node(start) and g.has_node(target)):
        return 0
    try:
        return sum(1 for _ in nx.all_simple_paths(g, start, target, cutoff=cutoff))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return 0
