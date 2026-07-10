"""Risk scoring — per-finding score and per-app aggregate (0-100, saturating).

dep_score = severity_weight x reachability x exploit_signal x depth   (for vulns)
app_score = 100 * (1 - exp(-weighted_raw / K))
            where weighted_raw = sum(dep_score) x criticality x internet
"""
from __future__ import annotations

import math

from ..models import Application, Finding
from ..util.constants import (
    CRITICALITY_MULTIPLIER,
    INTERNAL_FACTOR,
    INTERNET_FACING_FACTOR,
    REACHABLE_FACTOR,
    SEVERITY_WEIGHT,
    UNREACHABLE_FACTOR,
)

_SATURATION_K = 80.0


def reachability_factor(finding: Finding) -> float:
    # Only vulnerabilities have a meaningful reachability distinction.
    if finding.risk_type in ("vulnerable", "transitive_vuln") and finding.is_reachable is False:
        return UNREACHABLE_FACTOR
    return REACHABLE_FACTOR


def score_finding(finding: Finding) -> float:
    base = SEVERITY_WEIGHT[finding.severity]
    if finding.risk_type in ("vulnerable", "transitive_vuln"):
        exploit = 1.0 + (0.5 if finding.kev else 0.0) + finding.epss * 0.5
        depth = 1.0 if finding.is_direct else 0.7
        return base * reachability_factor(finding) * exploit * depth
    if finding.risk_type == "license_conflict":
        return base  # severity already reflects license risk_level
    if finding.risk_type == "unmaintained":
        return base * 0.5
    return 0.0


def app_risk_score(findings: list[Finding], app: Application) -> float:
    weighted_raw = sum(f.score for f in findings)
    weighted_raw *= CRITICALITY_MULTIPLIER[app.business_criticality]
    weighted_raw *= INTERNET_FACING_FACTOR if app.internet_facing else INTERNAL_FACTOR
    return round(100.0 * (1.0 - math.exp(-weighted_raw / _SATURATION_K)), 1)


def risk_band(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
