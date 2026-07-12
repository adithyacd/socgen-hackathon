"""Orchestrator: load -> graph -> engines -> score -> aggregate -> AnalysisResult.

Engines are added slice by slice. This module is the single place that wires them
together and produces the object the API and static export both serve.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import networkx as nx

from .config import settings
from .data.loader import load_dataset
from .data.official_loader import load_official_dataset
from .evaluation.evaluate import evaluate
from .engines.license import find_license_conflicts
from .engines.maintenance import find_unmaintained
from .engines.reachability import annotate_reachability
from .engines.transitive import annotate_paths
from .engines.vuln import find_vulnerabilities
from .graph.builder import build_graph, library_nodes
from .models import Application, Dataset, Finding
from .scoring.score import app_risk_score, risk_band, score_finding
from .schemas import AnalysisResult, AppRisk, Summary
from .util.constants import REFERENCE_DATE

RISK_TYPES = [
    "vulnerable", "transitive_vuln", "license_conflict",
    "transitive_license_conflict", "license_unknown", "unmaintained",
]
_LICENSE_TYPES = ("license_conflict", "transitive_license_conflict", "license_unknown")


def collect_findings(g, ds: Dataset) -> list[Finding]:
    """Run every engine and return the merged, annotated finding list.

    Vulnerabilities are detected, then transitive attack paths and reachability
    are annotated onto them. Later slices append license + maintenance findings.
    """
    findings: list[Finding] = []
    findings += find_vulnerabilities(g)
    annotate_paths(g, findings)        # transitive engine: attack paths
    annotate_reachability(g, findings)  # reachability engine: exploitable vs unreachable
    findings += find_license_conflicts(g, ds)
    findings += find_unmaintained(g)
    return _merge_by_node(findings)


def _merge_by_node(findings: list[Finding]) -> list[Finding]:
    """Collapse multiple findings on one dependency into a single primary finding.

    Priority (matches the ground-truth labels): reachable vuln > license conflict >
    unmaintained > unreachable vuln (suppressed). Other detected types are kept on
    `secondary_risks` so compounding risk is still visible.
    """
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.app_id, f.library, f.version)].append(f)

    merged: list[Finding] = []
    for _key, fs in groups.items():
        vulns = [f for f in fs if f.risk_type in ("vulnerable", "transitive_vuln")]
        reach_vulns = [f for f in vulns if f.is_reachable is not False]
        lic = [f for f in fs if f.risk_type in _LICENSE_TYPES]
        maint = [f for f in fs if f.risk_type == "unmaintained"]
        if reach_vulns:
            primary = reach_vulns[0]
        elif lic:
            primary = lic[0]
        elif maint:
            primary = maint[0]
        else:
            primary = vulns[0] if vulns else fs[0]
        primary.secondary_risks = sorted({f.risk_type for f in fs} - {primary.risk_type})
        merged.append(primary)
    return merged


def _is_exploitable_critical(f: Finding) -> bool:
    if f.risk_type not in ("vulnerable", "transitive_vuln") or f.severity != "critical":
        return False
    if f.is_reachable is False:  # synthetic reachability suppression
        return False
    expl = (f.exploitability or "").lower()
    return expl not in ("low", "none")  # official: low/none exploitability = not high-priority


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


@dataclass
class AnalysisContext:
    """Everything computed once and reused by the API (analysis + graph queries)."""

    ds: Dataset
    g: nx.DiGraph
    findings: list[Finding]
    result: AnalysisResult


def _load_dataset(data_dir: Optional[Path]) -> Dataset:
    if data_dir is not None:
        p = Path(data_dir)
        if (p / "sbom_dependencies.csv").exists():
            return load_official_dataset(p)
        return load_dataset(p)
    if settings.dataset == "official":
        return load_official_dataset(settings.official_data_dir)
    return load_dataset(settings.data_dir)


def analyze_dataset(ds: Dataset) -> AnalysisContext:
    """Run the full pipeline on an in-memory Dataset (used by disk load AND upload scan)."""
    g = build_graph(ds)
    findings = collect_findings(g, ds)
    for f in findings:
        f.score = score_finding(f)
    apps = _aggregate(ds, g, findings)
    summary = _summarize(apps, findings)
    metrics = evaluate(ds, findings)
    result = AnalysisResult(
        generated_at=REFERENCE_DATE.isoformat(),
        apps=apps, findings=findings, summary=summary, metrics=metrics,
    )
    return AnalysisContext(ds=ds, g=g, findings=findings, result=result)


def build_context(data_dir: Optional[Path] = None) -> AnalysisContext:
    return analyze_dataset(_load_dataset(data_dir))


def run_analysis(data_dir: Optional[Path] = None) -> AnalysisResult:
    return build_context(data_dir).result
