"""Incident briefs for the War Room — LLM-written when a key is present, else a
deterministic template. Either way the numbers come from the real impact object.
"""
from __future__ import annotations

import json

from ..schemas import WarRoomImpact
from .llm import llm_complete

_SYSTEM = (
    "You are the application security lead at a large bank, writing a concise "
    "incident brief for engineering leadership. Be precise, calm, and specific. "
    "Use only the facts in the JSON provided. 110 words max, plain prose, no headings. "
    "Lead with the exploitable blast radius, name the top app and its attack path, then "
    "the single remediation action and any upgrade conflict to watch."
)


def _facts(impact: WarRoomImpact) -> dict:
    top = impact.affected[0] if impact.affected else None
    return {
        "cve": impact.cve.cve_id,
        "library": impact.cve.affected_library,
        "cvss": impact.cve.cvss,
        "kev": impact.cve.kev,
        "fixed_version": impact.cve.fixed_version,
        "apps_affected": impact.affected_count,
        "apps_exploitable": impact.exploitable_count,
        "apps_suppressed": impact.affected_count - impact.exploitable_count,
        "blast_radius": impact.blast_radius,
        "top_app": None if not top else {
            "name": top.name,
            "criticality": top.business_criticality,
            "internet_facing": top.internet_facing,
            "exploitable": top.is_reachable,
            "attack_path": top.path,
        },
    }


def _template(impact: WarRoomImpact) -> str:
    cve = impact.cve
    exploit = impact.exploitable_count
    suppressed = impact.affected_count - exploit
    top = impact.affected[0] if impact.affected else None
    lead = (
        f"{cve.cve_id} in {cve.affected_library} (CVSS {cve.cvss}"
        f"{', CISA KEV' if cve.kev else ''}) is present in {impact.affected_count} "
        f"applications; {exploit} are actually exploitable and {suppressed} carry the "
        f"vulnerable code on an unreachable path."
    )
    focus = ""
    if top and top.is_reachable:
        chain = " → ".join(["app", *top.path]) if top.path else top.library
        focus = (
            f" Highest priority is {top.name} "
            f"({top.business_criticality}{', internet-facing' if top.internet_facing else ''}), "
            f"reached via {chain}."
        )
    action = (
        f" Remediate by upgrading {cve.affected_library} to {cve.fixed_version}."
        if cve.fixed_version else
        f" Remediate {cve.affected_library} per vendor guidance."
    )
    return lead + focus + action + f" Blast radius: {impact.blast_radius}."


def incident_brief(impact: WarRoomImpact) -> str:
    text = llm_complete(
        _SYSTEM,
        json.dumps(_facts(impact), indent=2),
        max_tokens=400,
        cache_key=f"incident_{impact.cve.cve_id}",
    )
    return text or _template(impact)
