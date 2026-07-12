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

_SATURATION_K = 48.0
_DECAY = 0.82  # the worst findings dominate; a long tail of minor ones barely adds


# Exploitability -> prioritization multiplier (official data's real signal).
_EXPLOIT_FACTOR = {"high": 1.3, "medium": 1.0, "low": 0.55, "none": 0.3, "": 1.0}
_LICENSE_TYPES = ("license_conflict", "transitive_license_conflict", "license_unknown")


def reachability_factor(finding: Finding) -> float:
    # Official data prioritizes via exploitability_factor instead; skip here.
    if finding.exploitability:
        return REACHABLE_FACTOR
    # Synthetic-only: unreachable vulns are down-weighted.
    if finding.risk_type in ("vulnerable", "transitive_vuln") and finding.is_reachable is False:
        return UNREACHABLE_FACTOR
    return REACHABLE_FACTOR


def exploitability_factor(finding: Finding) -> float:
    return _EXPLOIT_FACTOR.get((finding.exploitability or "").lower(), 1.0)


def score_finding(finding: Finding) -> float:
    base = SEVERITY_WEIGHT[finding.severity]
    if finding.risk_type in ("vulnerable", "transitive_vuln"):
        exploit = 1.0 + (0.5 if finding.kev else 0.0) + finding.epss * 0.5
        depth = 1.0 if finding.is_direct else 0.7
        return base * reachability_factor(finding) * exploitability_factor(finding) * exploit * depth
    if finding.risk_type in _LICENSE_TYPES:
        return base  # severity already reflects license risk_level
    if finding.risk_type == "unmaintained":
        return base * 0.5
    return 0.0


def app_risk_score(findings: list[Finding], app: Application) -> float:
    # Geometric decay over the worst-first findings so a big app doesn't auto-saturate.
    ranked = sorted((f.score for f in findings), reverse=True)
    weighted_raw = sum(s * (_DECAY ** i) for i, s in enumerate(ranked))
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
