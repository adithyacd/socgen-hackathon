"""Prioritization engine — marks each vulnerability finding as actionable or not.

Official data: driven by the CVE's real `exploitability` (HIGH/MEDIUM = actionable).
Synthetic data: driven by the used-edge reachability model. Either way this is a
PRIORITIZATION signal — it never changes whether a dependency is flagged as risky
(so the benchmark detection recall is unaffected); it decides what to surface first.
"""
from __future__ import annotations

import networkx as nx

from ..graph.builder import lib_node
from ..graph.traversal import used_reachable
from ..models import Finding

VULN_TYPES = ("vulnerable", "transitive_vuln")


def annotate_reachability(g: nx.DiGraph, findings: list[Finding]) -> None:
    cache: dict[str, set[str]] = {}
    for f in findings:
        if f.risk_type not in VULN_TYPES:
            continue
        if f.exploitability:
            # Official: actionable = high/medium exploitability.
            f.is_reachable = f.exploitability.lower() in ("high", "medium")
            if not f.is_reachable:
                f.detail = f"{f.detail} Exploitability {f.exploitability.upper()} — deprioritized."
            continue
        # Synthetic: used-edge reachability.
        reach = cache.get(f.app_id)
        if reach is None:
            reach = used_reachable(g, f.app_id)
            cache[f.app_id] = reach
        f.is_reachable = lib_node(f.app_id, f.library, f.version) in reach
        if f.is_reachable is False:
            f.detail = f"{f.detail} Present but UNREACHABLE — no used call path."
