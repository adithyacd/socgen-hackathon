"""Single source of truth for 'is this library unmaintained?'.

Imported by both the data generator (to write ground-truth labels) and the
maintenance engine (to detect), so they can never disagree.
"""
from __future__ import annotations

from datetime import date, timedelta

from .constants import REFERENCE_DATE, STALE_YEARS


def _parse(d: str) -> date | None:
    try:
        return date.fromisoformat(d)
    except (ValueError, TypeError):
        return None


def is_stale(last_updated: str, maintainer_count: int) -> bool:
    """True if not updated within STALE_YEARS, or single-maintainer and >1.5y old."""
    d = _parse(last_updated)
    if d is None:
        return False  # unknown date (e.g. uploaded manifest) is not treated as stale
    hard_cutoff = REFERENCE_DATE - timedelta(days=int(STALE_YEARS * 365))
    soft_cutoff = REFERENCE_DATE - timedelta(days=int(1.5 * 365))
    if d < hard_cutoff:
        return True
    if maintainer_count <= 1 and d < soft_cutoff:
        return True
    return False
