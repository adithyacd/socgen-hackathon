"""Shared constants so the generator and the engines agree on thresholds."""
from __future__ import annotations

from datetime import date

# Fixed "today" for the demo, so staleness is reproducible regardless of wall clock.
REFERENCE_DATE = date(2026, 4, 1)

# A library is "stale" if not updated within this many years.
STALE_YEARS = 2

# Severity ordering (ascending) + numeric weight used in scoring.
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.5}


def max_severity(severities):
    """Return the highest severity from an iterable (default 'low')."""
    best = "low"
    for s in severities:
        if SEVERITY_ORDER.index(s) > SEVERITY_ORDER.index(best):
            best = s
    return best

# Business criticality -> multiplier on aggregated app risk.
CRITICALITY_MULTIPLIER = {"critical": 1.5, "high": 1.25, "medium": 1.0, "low": 0.8}

# Reachability multiplier: unreachable vulns barely count (the FP-killer).
REACHABLE_FACTOR = 1.0
UNREACHABLE_FACTOR = 0.15

# Internet-facing apps carry more real-world risk.
INTERNET_FACING_FACTOR = 1.3
INTERNAL_FACTOR = 1.0
