"""Fix Optimizer — the cheapest path to safe.

Ranks library upgrades by how much exploitable risk each removes across the whole
portfolio (one upgrade of a shared library fixes many apps at once), and flags
version-constraint conflicts an upgrade would introduce (diamond conflicts).
"""
from __future__ import annotations

from collections import defaultdict

from .analysis import AnalysisContext
from .models import Finding
from .schemas import FixPlan, Upgrade, UpgradeConflict
from .util.semver import parse_version, satisfies_constraint

VULN_TYPES = ("vulnerable", "transitive_vuln")


def _exploitable_vulns(ctx: AnalysisContext) -> list[Finding]:
    return [f for f in ctx.findings if f.risk_type in VULN_TYPES and f.is_reachable is not False]


def _target_version(findings: list[Finding]) -> str:
    """Highest fixed version across all CVEs on a library — fixes them all."""
    fixed = [v for f in findings for v in f.fixed_versions.values() if v]
    parsed = [(parse_version(v), v) for v in fixed]
    parsed = [(p, raw) for p, raw in parsed if p is not None]
    if not parsed:
        return "latest"
    return max(parsed, key=lambda t: t[0])[1]


def _conflicts(ctx: AnalysisContext, library: str, to_version: str) -> list[UpgradeConflict]:
    out: dict[tuple, UpgradeConflict] = {}
    g = ctx.g
    for u, v, d in g.edges(data=True):
        vd = g.nodes[v]
        if vd.get("library") != library:
            continue
        constraint = d.get("version_constraint", "*")
        if constraint and constraint != "*" and not satisfies_constraint(to_version, constraint):
            parent = g.nodes[u].get("library", "application") if g.nodes[u].get("kind") != "app" else "application"
            # Dedupe by the reason (parent + constraint); keep a representative app.
            key = (parent, constraint)
            if key not in out:
                out[key] = UpgradeConflict(app_id=vd.get("app_id"), parent_library=parent, constraint=constraint)
    return list(out.values())


def build_fix_plan(ctx: AnalysisContext) -> FixPlan:
    vulns = _exploitable_vulns(ctx)
    by_lib: dict[str, list[Finding]] = defaultdict(list)
    for f in vulns:
        by_lib[f.library].append(f)

    upgrades: list[Upgrade] = []
    for lib, fs in by_lib.items():
        to_version = _target_version(fs)
        cves = sorted({c for f in fs for c in f.cve_ids})
        apps = sorted({f.app_id for f in fs})
        from_versions = sorted({f.version for f in fs})
        risk_removed = round(sum(f.score for f in fs), 1)
        criticals = sum(1 for f in fs if f.severity == "critical")
        upgrades.append(Upgrade(
            library=lib, to_version=to_version, from_versions=from_versions,
            cves_fixed=cves, apps_affected=apps, app_count=len(apps),
            risk_removed=risk_removed, criticals_removed=criticals,
            conflicts=_conflicts(ctx, lib, to_version),
        ))

    # Greedy: biggest risk reduction first (each library's coverage is disjoint,
    # so ranking by risk_removed is the optimal cover order).
    upgrades.sort(key=lambda u: (u.risk_removed, u.criticals_removed), reverse=True)

    return FixPlan(
        total_exploitable_risk=round(sum(f.score for f in vulns), 1),
        total_exploitable_criticals=sum(1 for f in vulns if f.severity == "critical"),
        total_exploitable_findings=len(vulns),
        recommended=upgrades,
    )
