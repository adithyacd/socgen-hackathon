"""Build a per-app-namespaced NetworkX dependency graph and overlay vulnerabilities.

Nodes:
  - app node:      "app:{app_id}"                (kind="app")
  - library node:  "{app_id}::{library}@{version}" (kind="library")

Library nodes are namespaced per app so each application owns its own dependency
tree — this keeps per-app reachability (the `used` overrides) correct even when
two apps share the same library@version.

Edge attributes: is_direct, used, version_constraint.
Library-node attributes: library, version, license, last_updated,
maintainer_count, app_id, is_direct, vulns (list[Vulnerability]).
"""
from __future__ import annotations

import networkx as nx

from ..models import APP_PARENT, Dataset, Vulnerability
from ..util.semver import version_in_range


def app_node(app_id: str) -> str:
    return f"app:{app_id}"


def lib_node(app_id: str, library: str, version: str) -> str:
    return f"{app_id}::{library}@{version}"


def build_graph(ds: Dataset) -> nx.DiGraph:
    g = nx.DiGraph()

    for app in ds.applications:
        g.add_node(app_node(app.app_id), kind="app", **app.model_dump())

    for dep in ds.dependencies:
        child = lib_node(dep.app_id, dep.library, dep.version)
        if not g.has_node(child):
            g.add_node(child, kind="library", app_id=dep.app_id, library=dep.library,
                       version=dep.version, license=dep.license,
                       last_updated=dep.last_updated, maintainer_count=dep.maintainer_count,
                       is_direct=False, vulns=[])
        if dep.is_direct:
            g.nodes[child]["is_direct"] = True

        if dep.parent_library == APP_PARENT:
            parent = app_node(dep.app_id)
        else:
            parent = lib_node(dep.app_id, dep.parent_library, dep.parent_version)
            if not g.has_node(parent):
                # Parent node may not have its own row yet; create a stub.
                g.add_node(parent, kind="library", app_id=dep.app_id,
                           library=dep.parent_library, version=dep.parent_version,
                           license="", last_updated="", maintainer_count=1,
                           is_direct=False, vulns=[])
        g.add_edge(parent, child, is_direct=dep.is_direct, used=dep.used,
                   version_constraint=dep.version_constraint)

    _overlay_vulnerabilities(g, ds.vulnerabilities)
    return g


def _overlay_vulnerabilities(g: nx.DiGraph, vulns: list[Vulnerability]) -> None:
    by_lib: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        by_lib.setdefault(v.affected_library, []).append(v)
    for _node, data in g.nodes(data=True):
        if data.get("kind") != "library":
            continue
        matches = [v for v in by_lib.get(data["library"], [])
                   if version_in_range(data["version"], v.version_range)]
        data["vulns"] = matches


def library_nodes(g: nx.DiGraph, app_id: str):
    """Yield (node_id, data) for every library node belonging to an app."""
    for node, data in g.nodes(data=True):
        if data.get("kind") == "library" and data.get("app_id") == app_id:
            yield node, data
