"""API output schemas (what the dashboard consumes)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .models import Finding


class AppRisk(BaseModel):
    app_id: str
    name: str
    business_criticality: str
    owner: str
    internet_facing: bool
    environment: str
    ecosystem: str
    license_context: str
    risk_score: float
    risk_band: str
    dependency_count: int
    direct_count: int
    counts: dict[str, int]          # risk_type -> count (+ exploitable_criticals)
    top_findings: list[Finding]


class Summary(BaseModel):
    app_count: int
    dependency_count: int
    finding_count: int
    exploitable_criticals: int
    counts: dict[str, int]          # risk_type totals across the portfolio
    highest_risk_app: str


class AnalysisResult(BaseModel):
    generated_at: str
    apps: list[AppRisk]
    findings: list[Finding]
    summary: Summary
    metrics: dict[str, Any] = {}     # evaluation harness output (Slice 4)


class GraphNode(BaseModel):
    id: str
    library: str
    version: str
    kind: str                    # "app" | "library"
    is_direct: bool = False
    is_vulnerable: bool = False
    is_reachable: bool | None = None
    exploitability: str = ""     # official: high/medium/low/none
    severity: str | None = None  # worst finding severity on this node
    risk_types: list[str] = []
    cve_ids: list[str] = []
    license: str = ""
    last_updated: str = ""
    maintainer_count: int = 0
    score: float = 0.0
    depth: int = 0               # hops from the app node


class GraphEdge(BaseModel):
    source: str
    target: str
    used: bool = True
    is_direct: bool = False


class AppGraph(BaseModel):
    app: AppRisk
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    findings: list[Finding]


class WarRoomCve(BaseModel):
    cve_id: str
    description: str
    cvss: float
    severity: str
    kev: bool
    epss: float
    affected_library: str
    fixed_version: str | None = None
    affected_apps: int
    exploitable_apps: int


class AppImpact(BaseModel):
    app_id: str
    name: str
    business_criticality: str
    internet_facing: bool
    environment: str
    library: str
    version: str
    is_direct: bool
    is_reachable: bool
    exploitability: str = ""
    path: list[str]


class WarRoomImpact(BaseModel):
    cve: WarRoomCve
    affected: list[AppImpact]
    affected_count: int
    exploitable_count: int
    blast_radius: str
    narrative: str = ""


class UpgradeConflict(BaseModel):
    app_id: str
    parent_library: str
    constraint: str


class Upgrade(BaseModel):
    library: str
    to_version: str
    from_versions: list[str]
    cves_fixed: list[str]
    apps_affected: list[str]
    app_count: int
    risk_removed: float
    criticals_removed: int
    conflicts: list[UpgradeConflict] = []


class FixPlan(BaseModel):
    total_exploitable_risk: float
    total_exploitable_criticals: int
    total_exploitable_findings: int
    recommended: list[Upgrade]


class CopilotRequest(BaseModel):
    question: str


class CopilotAnswer(BaseModel):
    question: str
    answer: str
    query: dict[str, Any]
    matches: list[dict[str, Any]]
    match_count: int
    source: str  # "llm" | "rules"
