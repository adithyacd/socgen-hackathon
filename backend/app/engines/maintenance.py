"""Maintenance engine — flag stale / abandoned dependencies.

Uses the shared is_stale predicate (same one the generator labels with), so
detection and ground truth never disagree.
"""
from __future__ import annotations

import networkx as nx

from ..models import Finding
from ..util.staleness import is_stale


def find_unmaintained(g: nx.DiGraph) -> list[Finding]:
    findings: list[Finding] = []
    for _node, data in g.nodes(data=True):
        if data.get("kind") != "library":
            continue
        last_updated = data.get("last_updated", "")
        maintainers = data.get("maintainer_count", 1)
        if is_stale(last_updated, maintainers):
            solo = maintainers <= 1
            findings.append(Finding(
                app_id=data["app_id"], library=data["library"], version=data["version"],
                is_direct=bool(data.get("is_direct")),
                risk_type="unmaintained", severity="medium",
                detail=f"Unmaintained: last updated {last_updated}, "
                       f"{maintainers} maintainer{'' if solo else 's'}"
                       f"{' (bus factor = 1)' if solo else ''}.",
            ))
    return findings
