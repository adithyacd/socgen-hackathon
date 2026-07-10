"""Minimal semver-range matching for vulnerability version ranges.

Ranges are comma-joined clauses, each `<op><version>`, e.g. ">=2.0.0,<2.17.1".
A bare "*" (or empty) matches everything.
"""
from __future__ import annotations

from typing import Optional

from packaging.version import InvalidVersion, Version

_OPS = ("<=", ">=", "==", "!=", "<", ">")


def parse_version(v: str) -> Optional[Version]:
    try:
        return Version(v)
    except (InvalidVersion, TypeError):
        return None


def _compare(a: Version, op: str, b: Version) -> bool:
    if op == ">=":
        return a >= b
    if op == "<=":
        return a <= b
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    if op == ">":
        return a > b
    if op == "<":
        return a < b
    return False


def version_in_range(version: str, range_str: str) -> bool:
    """True if `version` satisfies every clause in `range_str`."""
    if not range_str or range_str.strip() == "*":
        return True
    ver = parse_version(version)
    if ver is None:
        return False
    for clause in range_str.split(","):
        clause = clause.strip()
        if not clause:
            continue
        op = next((o for o in _OPS if clause.startswith(o)), "==")
        bound = clause[len(op):].strip() if clause.startswith(op) else clause
        bver = parse_version(bound)
        if bver is None:
            return False
        if not _compare(ver, op, bver):
            return False
    return True


def satisfies_constraint(version: str, constraint: str) -> bool:
    """Alias used by the optimizer's conflict detection."""
    return version_in_range(version, constraint)
