"""Pydantic domain models — the data contract shared across every engine."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel

Criticality = Literal["critical", "high", "medium", "low"]
Severity = Literal["critical", "high", "medium", "low"]
Ecosystem = Literal["npm", "pypi", "maven"]
Environment = Literal["prod", "staging", "dev"]
LicenseCategory = Literal["permissive", "weak-copyleft", "copyleft", "proprietary", "unknown"]
RiskType = Literal["vulnerable", "license_conflict", "unmaintained", "transitive_vuln", "clean"]

# Sentinel for the synthetic "parent is the application itself" edge.
APP_PARENT = "__APP__"


class Application(BaseModel):
    app_id: str
    name: str
    business_criticality: Criticality
    owner: str
    internet_facing: bool
    environment: Environment
    ecosystem: Ecosystem
    license_context: str  # the app's own license posture, e.g. "Proprietary"


class Dependency(BaseModel):
    """One occurrence of a library in an app's dependency tree (an edge)."""

    app_id: str
    library: str
    version: str
    license: str
    is_direct: bool
    parent_library: str = APP_PARENT  # APP_PARENT for direct deps
    parent_version: str = ""          # "" for direct deps
    used: bool = True                 # is this edge actually exercised (reachability)
    version_constraint: str = "*"     # semver range the parent requires
    last_updated: str = ""            # ISO date YYYY-MM-DD
    maintainer_count: int = 1

    @property
    def node_id(self) -> str:
        return f"{self.library}@{self.version}"

    @property
    def parent_node_id(self) -> str:
        if self.parent_library == APP_PARENT:
            return f"app:{self.app_id}"
        return f"{self.parent_library}@{self.parent_version}"


class Vulnerability(BaseModel):
    cve_id: str
    affected_library: str
    version_range: str  # e.g. ">=2.0.0,<2.17.1"
    cvss: float
    severity: Severity
    patch_available: bool
    fixed_version: Optional[str] = None
    vulnerable_symbol: str = ""
    kev: bool = False   # CISA Known-Exploited
    epss: float = 0.0   # 0..1 exploit-prediction score
    published: str = ""
    description: str = ""


class LicenseRule(BaseModel):
    license: str
    category: LicenseCategory
    incompatible_with: list[str] = []  # app license_context values it conflicts with
    risk_level: Severity = "low"


class Label(BaseModel):
    """Ground truth for the evaluation harness."""

    app_id: str
    library: str
    version: str
    is_risk: bool
    risk_type: RiskType
    severity: Severity
    is_reachable: bool
    explanation: str


class Finding(BaseModel):
    """A single detected risk on one dependency of one app (engine output)."""

    app_id: str
    library: str
    version: str
    is_direct: bool
    risk_type: RiskType
    severity: Severity
    cve_ids: list[str] = []
    is_reachable: Optional[bool] = None  # set by the reachability engine
    detail: str = ""
    score: float = 0.0
    paths: list[list[str]] = []          # attack paths (library@version chains)
    fixed_versions: dict[str, Optional[str]] = {}  # cve_id -> fixed_version
    max_cvss: float = 0.0
    kev: bool = False
    epss: float = 0.0

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.app_id, self.library, self.version, self.risk_type)


class Dataset(BaseModel):
    """The whole synthetic dataset in memory."""

    applications: list[Application]
    dependencies: list[Dependency]
    vulnerabilities: list[Vulnerability]
    license_rules: list[LicenseRule]
    labels: list[Label] = []
