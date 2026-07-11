"""Zero-Day War Room — portfolio-wide impact of a single CVE, in one query.

Answers 'when this CVE drops, which apps are exposed, through which path, and which
are actually exploitable?' across every application at once.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

from .analysis import AnalysisContext
from .schemas import AppImpact, WarRoomCve, WarRoomImpact

_CRIT_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _cve_meta(ctx: AnalysisContext, cve_id: str):
    return next((v for v in ctx.ds.vulnerabilities if v.cve_id == cve_id), None)


def notable_cves(ctx: AnalysisContext) -> list[WarRoomCve]:
    """CVEs that actually match something in the portfolio, worst first."""
    by_cve: dict[str, list] = defaultdict(list)
    for f in ctx.findings:
        for cve in f.cve_ids:
            by_cve[cve].append(f)

    out: list[WarRoomCve] = []
    for cve, fs in by_cve.items():
        v = _cve_meta(ctx, cve)
        if v is None:
            continue
        affected = {f.app_id for f in fs}
        exploitable = {f.app_id for f in fs if f.is_reachable is not False}
        out.append(WarRoomCve(
            cve_id=cve, description=v.description, cvss=v.cvss, severity=v.severity,
            kev=v.kev, epss=v.epss, affected_library=v.affected_library,
            fixed_version=v.fixed_version, affected_apps=len(affected),
            exploitable_apps=len(exploitable),
        ))
    out.sort(key=lambda c: (not c.kev, -c.cvss, -c.exploitable_apps))
    return out


def _blast_radius(affected: list[AppImpact], exploitable: int) -> str:
    if exploitable == 0:
        return "No exploitable exposure — the vulnerable code is present but unreachable everywhere."
    crit = [a for a in affected if a.is_reachable and a.business_criticality == "critical"]
    net = [a for a in affected if a.is_reachable and a.internet_facing]
    parts = [f"{exploitable} app(s) exploitable"]
    if crit:
        parts.append(f"{len(crit)} business-critical")
    if net:
        parts.append(f"{len(net)} internet-facing")
    return " · ".join(parts)


def war_room_impact(ctx: AnalysisContext, cve_id: str) -> Optional[WarRoomImpact]:
    v = _cve_meta(ctx, cve_id)
    if v is None:
        return None
    fs = [f for f in ctx.findings if cve_id in f.cve_ids]
    app_by_id = {a.app_id: a for a in ctx.result.apps}

    affected: list[AppImpact] = []
    for f in fs:
        app = app_by_id.get(f.app_id)
        if app is None:
            continue
        affected.append(AppImpact(
            app_id=app.app_id, name=app.name, business_criticality=app.business_criticality,
            internet_facing=app.internet_facing, environment=app.environment,
            library=f.library, version=f.version, is_direct=f.is_direct,
            is_reachable=f.is_reachable is not False,
            path=f.paths[0] if f.paths else [],
        ))
    # Rank: exploitable first, then business criticality, then internet-facing.
    affected.sort(key=lambda a: (not a.is_reachable, _CRIT_ORDER[a.business_criticality],
                                 not a.internet_facing))
    exploitable = sum(1 for a in affected if a.is_reachable)

    cve = WarRoomCve(
        cve_id=v.cve_id, description=v.description, cvss=v.cvss, severity=v.severity,
        kev=v.kev, epss=v.epss, affected_library=v.affected_library,
        fixed_version=v.fixed_version, affected_apps=len(affected),
        exploitable_apps=exploitable,
    )
    return WarRoomImpact(
        cve=cve, affected=affected, affected_count=len(affected),
        exploitable_count=exploitable, blast_radius=_blast_radius(affected, exploitable),
    )
