"""Orchestrator: load -> graph -> engines -> score -> aggregate -> AnalysisResult.

Engines are added slice by slice. This module is the single place that wires them
together and produces the object the API and static export both serve.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Optional

from .data.loader import load_dataset
from .engines.vuln import find_vulnerabilities
from .graph.builder import build_graph, library_nodes
from .models import Application, Dataset, Finding
from .scoring.score import app_risk_score, risk_band, score_finding
from .schemas import AnalysisResult, AppRisk, Summary
from .util.constants import REFERENCE_DATE

RISK_TYPES = ["vulnerable", "transitive_vuln", "license_conflict", "unmaintained"]


def collect_findings(g, ds: Dataset) -> list[Finding]:
    """Run every engine and return the merged finding list.

    Slice 1: vulnerabilities only. Later slices append license/maintenance and
    annotate reachability + attack paths.
    """
    findings: list[Finding] = []
    findings += find_vulnerabilities(g)
    return findings


def _is_exploitable_critical(f: Finding) -> bool:
    return (
        f.risk_type in ("vulnerable", "transitive_vuln")
        and f.severity == "critical"
        and f.is_reachable is not False
    )


def _aggregate(ds: Dataset, g, findings: list[Finding]) -> list[AppRisk]:
    by_app: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_app[f.app_id].append(f)

    apps: list[AppRisk] = []
    for app in ds.applications:
        app_findings = by_app.get(app.app_id, [])
        lib_nodes = list(library_nodes(g, app.app_id))
        direct = sum(1 for _n, d in lib_nodes if d.get("is_direct"))
        counts = {rt: sum(1 for f in app_findings if f.risk_type == rt) for rt in RISK_TYPES}
        counts["exploitable_criticals"] = sum(1 for f in app_findings if _is_exploitable_critical(f))
        score = app_risk_score(app_findings, app)
        top = sorted(app_findings, key=lambda f: f.score, reverse=True)[:5]
        apps.append(AppRisk(
            app_id=app.app_id, name=app.name,
            business_criticality=app.business_criticality, owner=app.owner,
            internet_facing=app.internet_facing, environment=app.environment,
            ecosystem=app.ecosystem, license_context=app.license_context,
            risk_score=score, risk_band=risk_band(score),
            dependency_count=len(lib_nodes), direct_count=direct,
            counts=counts, top_findings=top,
        ))
    apps.sort(key=lambda a: a.risk_score, reverse=True)
    return apps


def _summarize(apps: list[AppRisk], findings: list[Finding]) -> Summary:
    counts = {rt: sum(1 for f in findings if f.risk_type == rt) for rt in RISK_TYPES}
    return Summary(
        app_count=len(apps),
        dependency_count=sum(a.dependency_count for a in apps),
        finding_count=len(findings),
        exploitable_criticals=sum(1 for f in findings if _is_exploitable_critical(f)),
        counts=counts,
        highest_risk_app=apps[0].name if apps else "",
    )


def run_analysis(data_dir: Optional[Path] = None) -> AnalysisResult:
    ds = load_dataset(data_dir)
    g = build_graph(ds)
    findings = collect_findings(g, ds)
    for f in findings:
        f.score = score_finding(f)
    apps = _aggregate(ds, g, findings)
    summary = _summarize(apps, findings)
    return AnalysisResult(
        generated_at=REFERENCE_DATE.isoformat(),
        apps=apps, findings=findings, summary=summary,
    )
