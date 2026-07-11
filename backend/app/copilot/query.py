"""Grounded copilot: natural-language question -> structured query -> real results.

The LLM (when available) only translates the question into a constrained QuerySpec;
the answer is computed deterministically over the analysis data, so the copilot can
explain but never fabricate. Without a key, a keyword parser handles common questions.
"""
from __future__ import annotations

import json
from typing import Optional

from pydantic import BaseModel, ValidationError

from ..analysis import AnalysisContext
from ..narratives.llm import llm_complete
from ..schemas import CopilotAnswer

RISK_TYPES = {"vulnerable", "transitive_vuln", "license_conflict", "unmaintained"}
SEVERITIES = {"critical", "high", "medium", "low"}

# Suggested questions surfaced in the UI and precomputed for the static build.
SUGGESTIONS = [
    "Which internet-facing apps have exploitable criticals?",
    "Show all GPL license conflicts",
    "Which apps are exposed to Log4Shell?",
    "List unmaintained libraries",
    "Which transitive dependencies are exploitable?",
]


class QuerySpec(BaseModel):
    entity: str = "findings"                 # "apps" | "findings"
    risk_type: Optional[str] = None
    severity: Optional[str] = None
    reachable: Optional[bool] = None
    license_family: Optional[str] = None     # e.g. "GPL"
    internet_facing: Optional[bool] = None
    business_criticality: Optional[str] = None
    library: Optional[str] = None
    cve: Optional[str] = None
    transitive: Optional[bool] = None


_SCHEMA_HELP = (
    "Translate the user's question into a JSON object with these optional keys: "
    'entity ("apps"|"findings"), risk_type ("vulnerable"|"transitive_vuln"|'
    '"license_conflict"|"unmaintained"), severity ("critical"|"high"|"medium"|"low"), '
    "reachable (bool, true = exploitable), license_family (e.g. \"GPL\"), "
    "internet_facing (bool), business_criticality (severity string), library (name substring), "
    "cve (CVE id), transitive (bool). Output ONLY the JSON object, no prose."
)


def parse_rule_based(q: str) -> QuerySpec:
    ql = q.lower()
    spec = QuerySpec()
    if "app" in ql and "librar" not in ql and "dependenc" not in ql:
        spec.entity = "apps"
    if "gpl" in ql or "agpl" in ql or "copyleft" in ql or "licen" in ql:
        spec.risk_type = "license_conflict"
        if "gpl" in ql:
            spec.license_family = "GPL"
    if "unmaintain" in ql or "abandon" in ql or "stale" in ql or "outdated" in ql:
        spec.risk_type = "unmaintained"
    if "exploitab" in ql or "reachab" in ql:
        spec.reachable = True
    if "unreachab" in ql or "suppress" in ql or "not exploitab" in ql:
        spec.reachable = False
    if "critical" in ql:
        spec.severity = "critical"
    elif "high" in ql:
        spec.severity = "high"
    if "internet" in ql or "external" in ql or "public" in ql:
        spec.internet_facing = True
    if "transitive" in ql or "nested" in ql or "indirect" in ql:
        spec.transitive = True
        if not spec.risk_type:
            spec.risk_type = "transitive_vuln"
    if "log4j" in ql or "log4shell" in ql:
        spec.library = "log4j"
    if "vulnerab" in ql and not spec.risk_type:
        spec.risk_type = "vulnerable"
    for tok in q.replace(",", " ").split():
        if tok.upper().startswith("CVE-"):
            spec.cve = tok.upper()
    return spec


def parse_llm(q: str) -> Optional[QuerySpec]:
    raw = llm_complete(
        _SCHEMA_HELP,
        q,
        max_tokens=200,
        cache_key=f"copilot_q_{abs(hash(q.lower().strip())) % (10**10)}",
    )
    if not raw:
        return None
    try:
        start, end = raw.index("{"), raw.rindex("}") + 1
        return QuerySpec(**json.loads(raw[start:end]))
    except (ValueError, ValidationError):
        return None


def _app_meta(ctx: AnalysisContext) -> dict:
    return {a.app_id: a for a in ctx.result.apps}


def execute(ctx: AnalysisContext, spec: QuerySpec):
    apps = _app_meta(ctx)
    rows = []
    for f in ctx.findings:
        app = apps.get(f.app_id)
        if app is None:
            continue
        if spec.risk_type:
            types = {f.risk_type, *f.secondary_risks}
            if spec.risk_type not in types:
                continue
        if spec.severity and f.severity != spec.severity:
            continue
        if spec.reachable is not None:
            is_reach = f.is_reachable is not False
            if is_reach != spec.reachable:
                continue
        if spec.transitive is not None and f.is_direct == spec.transitive:
            continue
        if spec.library and spec.library.lower() not in f.library.lower():
            continue
        if spec.cve and spec.cve not in f.cve_ids:
            continue
        if spec.license_family and spec.license_family.lower() not in f.detail.lower():
            continue
        if spec.internet_facing is not None and app.internet_facing != spec.internet_facing:
            continue
        if spec.business_criticality and app.business_criticality != spec.business_criticality:
            continue
        rows.append({
            "app_id": f.app_id, "app": app.name, "library": f.library, "version": f.version,
            "risk_type": f.risk_type, "severity": f.severity,
            "reachable": f.is_reachable is not False if f.risk_type.endswith("vuln") else None,
            "cves": f.cve_ids,
        })
    if spec.entity == "apps":
        seen, out = set(), []
        for r in rows:
            if r["app_id"] not in seen:
                seen.add(r["app_id"])
                out.append({"app_id": r["app_id"], "app": r["app"]})
        return out
    return rows


def _describe(spec: QuerySpec) -> str:
    bits = []
    if spec.severity:
        bits.append(spec.severity)
    if spec.reachable is True:
        bits.append("exploitable")
    if spec.reachable is False:
        bits.append("unreachable")
    if spec.transitive:
        bits.append("transitive")
    if spec.risk_type == "license_conflict":
        bits.append(f"{spec.license_family or ''} license-conflicting".strip())
    elif spec.risk_type == "unmaintained":
        bits.append("unmaintained")
    elif spec.risk_type in ("vulnerable", "transitive_vuln"):
        bits.append("vulnerable")
    if spec.library:
        bits.append(f"{spec.library} ")
    noun = "applications" if spec.entity == "apps" else "dependencies"
    if spec.internet_facing:
        noun = "internet-facing " + noun
    return f"{' '.join(bits)} {noun}".strip()


def answer(ctx: AnalysisContext, question: str) -> CopilotAnswer:
    spec = parse_llm(question)
    source = "llm"
    if spec is None:
        spec = parse_rule_based(question)
        source = "rules"

    results = execute(ctx, spec)
    n = len(results)
    desc = _describe(spec)
    if n == 0:
        text = f"No {desc} found in the current portfolio."
    else:
        if spec.entity == "apps":
            names = ", ".join(r["app"] for r in results[:8])
            text = f"{n} {desc}: {names}{'…' if n > 8 else ''}."
        else:
            preview = ", ".join(f"{r['library']} in {r['app']}" for r in results[:6])
            text = f"{n} {desc}: {preview}{'…' if n > 6 else ''}."

    return CopilotAnswer(
        question=question, answer=text, query=spec.model_dump(exclude_none=True),
        matches=results[:50], match_count=n, source=source,
    )
