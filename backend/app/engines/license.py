"""License engine — flag dependencies whose license conflicts with the app context.

Mirrors the generator's rule so detection matches ground truth: a library's
license (or the 'Unknown' fallback for unlisted licenses) is a conflict when the
app's license_context appears in the rule's incompatible_with list.
"""
from __future__ import annotations

import networkx as nx

from ..models import Dataset, Finding


def find_license_conflicts(g: nx.DiGraph, ds: Dataset) -> list[Finding]:
    rules = {r.license: r for r in ds.license_rules}
    unknown = rules.get("Unknown")
    app_ctx = {a.app_id: a.license_context for a in ds.applications}

    findings: list[Finding] = []
    for _node, data in g.nodes(data=True):
        if data.get("kind") != "library":
            continue
        lic = data.get("license", "")
        rule = rules.get(lic, unknown)
        if rule is None:
            continue
        ctx = app_ctx.get(data["app_id"])
        if not (ctx and ctx in rule.incompatible_with):
            continue
        is_direct = bool(data.get("is_direct"))
        is_unknown = rule.category == "unknown"
        if is_unknown:
            risk_type, why = "license_unknown", f"License '{lic}' is unrecognized — legal review needed."
        elif is_direct:
            risk_type, why = "license_conflict", f"Copyleft license '{lic}' is incompatible with the {ctx} application."
        else:
            risk_type, why = "transitive_license_conflict", f"Transitive copyleft license '{lic}' incompatible with the {ctx} application."
        findings.append(Finding(
            app_id=data["app_id"], library=data["library"], version=data["version"],
            is_direct=is_direct, risk_type=risk_type, severity=rule.risk_level, detail=why,
        ))
    return findings
