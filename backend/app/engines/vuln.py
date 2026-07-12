"""Vulnerability engine — turn overlaid CVEs into Findings.

Version-range matching already happened during graph overlay, so here we simply
read the `vulns` attribute on each library node.
"""
from __future__ import annotations

import networkx as nx

from ..models import Finding
from ..util.constants import max_severity

_EXPLOIT_ORDER = ["none", "low", "medium", "high"]


def _max_exploitability(vulns) -> str:
    best = ""
    for v in vulns:
        e = (getattr(v, "exploitability", "") or "").lower()
        if e in _EXPLOIT_ORDER and (best == "" or _EXPLOIT_ORDER.index(e) > _EXPLOIT_ORDER.index(best)):
            best = e
    return best


def find_vulnerabilities(g: nx.DiGraph) -> list[Finding]:
    findings: list[Finding] = []
    for _node, data in g.nodes(data=True):
        if data.get("kind") != "library":
            continue
        vulns = data.get("vulns", [])
        if not vulns:
            continue
        cve_ids = [v.cve_id for v in vulns]
        severity = max_severity(v.severity for v in vulns)
        max_cvss = max(v.cvss for v in vulns)
        kev = any(v.kev for v in vulns)
        epss = max((v.epss for v in vulns), default=0.0)
        fixed = {v.cve_id: v.fixed_version for v in vulns}
        is_direct = bool(data.get("is_direct"))
        findings.append(Finding(
            app_id=data["app_id"], library=data["library"], version=data["version"],
            is_direct=is_direct,
            risk_type="vulnerable" if is_direct else "transitive_vuln",
            severity=severity, cve_ids=cve_ids, exploitability=_max_exploitability(vulns),
            detail=f"{len(cve_ids)} known vulnerabilit{'y' if len(cve_ids) == 1 else 'ies'} "
                   f"(max CVSS {max_cvss}){' — CISA KEV' if kev else ''}.",
            fixed_versions=fixed, max_cvss=max_cvss, kev=kev, epss=epss,
        ))
    return findings
