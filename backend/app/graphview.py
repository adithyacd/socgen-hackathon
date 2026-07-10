"""Build the per-app dependency graph payload the dashboard renders (Cytoscape)."""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Optional

from .analysis import AnalysisContext
from .graph.builder import app_node, library_nodes
from .graph.traversal import used_reachable
from .schemas import AppGraph, GraphEdge, GraphNode
from .util.constants import max_severity


def _depths(g, start: str) -> dict[str, int]:
    depth = {start: 0}
    dq = deque([start])
    while dq:
        n = dq.popleft()
        for _u, v in g.out_edges(n):
            if v not in depth:
                depth[v] = depth[n] + 1
                dq.append(v)
    return depth


def build_app_graph(ctx: AnalysisContext, app_id: str) -> Optional[AppGraph]:
    app_risk = next((a for a in ctx.result.apps if a.app_id == app_id), None)
    if app_risk is None:
        return None

    g = ctx.g
    app_findings = [f for f in ctx.findings if f.app_id == app_id]
    fmap: dict[tuple, list] = defaultdict(list)
    for f in app_findings:
        fmap[(f.library, f.version)].append(f)

    reach = used_reachable(g, app_id)
    start = app_node(app_id)
    depth = _depths(g, start)

    nodes: list[GraphNode] = [
        GraphNode(id=start, library=app_risk.name, version="", kind="app", depth=0)
    ]
    for node, data in library_nodes(g, app_id):
        fs = fmap.get((data["library"], data["version"]), [])
        vuln_fs = [f for f in fs if f.risk_type in ("vulnerable", "transitive_vuln")]
        severity = max_severity([f.severity for f in fs]) if fs else None
        cve_ids = sorted({c for f in vuln_fs for c in f.cve_ids})
        is_reachable = (node in reach) if vuln_fs else None
        risk_types = sorted({rt for f in fs for rt in [f.risk_type, *f.secondary_risks]})
        nodes.append(GraphNode(
            id=node, library=data["library"], version=data["version"], kind="library",
            is_direct=bool(data.get("is_direct")), is_vulnerable=bool(vuln_fs),
            is_reachable=is_reachable, severity=severity,
            risk_types=risk_types, cve_ids=cve_ids,
            license=data.get("license", ""), last_updated=data.get("last_updated", ""),
            maintainer_count=data.get("maintainer_count", 0),
            score=max((f.score for f in fs), default=0.0), depth=depth.get(node, 1),
        ))

    edges: list[GraphEdge] = []
    for u, v, d in g.edges(data=True):
        if g.nodes[u].get("app_id") != app_id:
            continue
        edges.append(GraphEdge(source=u, target=v, used=bool(d.get("used", True)),
                               is_direct=bool(d.get("is_direct"))))

    app_findings.sort(key=lambda f: f.score, reverse=True)
    return AppGraph(app=app_risk, nodes=nodes, edges=edges, findings=app_findings)
