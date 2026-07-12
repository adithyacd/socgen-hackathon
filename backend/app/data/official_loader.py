"""Load the OFFICIAL Société Générale PB-10 sample data into our internal models.

Maps their schema (applications.json, sbom_dependencies.csv, vulnerability_db.json,
license_rules.json, transitive_dependencies.json, dependency_labels.csv) onto the same
Dataset/Dependency edge model the engines already use, so the graph, engines, scoring,
and dashboard carry over. This is the dataset judges score against.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Optional


def _read(path: Path) -> str:
    """Official files are a mix of UTF-8 and Windows-1252 (em-dashes). Try both."""
    data = path.read_bytes()
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _rows(path: Path):
    return list(csv.DictReader(io.StringIO(_read(path))))

from ..models import (
    APP_PARENT,
    Application,
    Dataset,
    Dependency,
    Label,
    LicenseRule,
    Vulnerability,
)

_CRIT = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "NONE": "low"}
_RISK = {
    "NONE": "clean",
    "VULNERABLE_DEPENDENCY": "vulnerable",
    "TRANSITIVE_VULNERABILITY": "transitive_vuln",
    "LICENSE_CONFLICT": "license_conflict",
    "TRANSITIVE_LICENSE_CONFLICT": "transitive_license_conflict",
    "LICENSE_UNKNOWN": "license_unknown",
    "UNMAINTAINED": "unmaintained",
}


def _apps(d: Path) -> list[Application]:
    out = []
    for a in json.loads(_read(d / "applications.json")):
        out.append(Application(
            app_id=a["app_id"], name=a["name"],
            business_criticality=_CRIT.get(a["criticality"], "medium"),
            owner=a.get("business_owner", a.get("department", "")),
            internet_facing=a.get("deployment") == "cloud",
            environment=a.get("deployment", ""),
            ecosystem=a.get("language", ""),
            license_context=a.get("license_model", "proprietary"),
        ))
    return out


def _vulns(d: Path) -> list[Vulnerability]:
    out = []
    for v in json.loads(_read(d / "vulnerability_db.json")):
        out.append(Vulnerability(
            cve_id=v["cve_id"], affected_library=v["library"],
            affected_versions=v.get("affected_versions", []),
            cvss=v.get("cvss_score", 0.0), severity=_SEV.get(v.get("severity", "LOW"), "low"),
            patch_available=v.get("patch_available", False), fixed_version=v.get("fixed_version"),
            exploitability=str(v.get("exploitability", "MEDIUM")).lower(),
            published=v.get("published_date", ""), description=v.get("description", ""),
        ))
    return out


def _rules(d: Path) -> list[LicenseRule]:
    out = []
    for r in json.loads(_read(d / "license_rules.json")):
        viral = r.get("viral", False)
        compat = r.get("compatible_with_proprietary", True)
        category = "copyleft" if viral else ("unknown" if r["license"] == "UNKNOWN" else "permissive")
        out.append(LicenseRule(
            license=r["license"], category=category,
            incompatible_with=[] if compat else ["proprietary", "internal-only"],
            risk_level=_SEV.get(r.get("risk_level", "LOW"), "low"),
        ))
    return out


def _labels(d: Path) -> list[Label]:
    out = []
    for row in _rows(d / "dependency_labels.csv"):
        if True:
            out.append(Label(
                app_id=row["application_id"], library=row["library"], version=row["version"],
                is_risk=str(row["is_risky"]).strip().lower() == "true",
                risk_type=_RISK.get(row["risk_type"], "clean"),
                severity=_SEV.get(row["severity"], "low"), is_reachable=True,
                explanation=row.get("explanation", ""),
            ))
    return out


def _parse_children(field: str):
    for part in (field or "").split(";"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        lib, ver = part.rsplit(":", 1)
        yield lib.strip(), ver.strip()


def load_official_dataset(data_dir: Path) -> Dataset:
    d = Path(data_dir)

    # SBOM rows -> node metadata + direct/transitive rows.
    sbom_rows = _rows(d / "sbom_dependencies.csv")
    meta: dict[tuple, dict] = {}
    for r in sbom_rows:
        meta[(r["application_id"], r["library"], r["version"])] = {
            "license": r.get("license", "UNKNOWN"),
            "last_updated": r.get("last_updated", ""),
            "type": r.get("dependency_type", "direct"),
        }

    deps: list[Dependency] = []
    seen: set[tuple] = set()

    def emit(app_id, plib, pver, lib, ver, is_direct):
        key = (app_id, plib, pver, lib, ver)
        if key in seen:
            return
        seen.add(key)
        m = meta.get((app_id, lib, ver), {})
        deps.append(Dependency(
            app_id=app_id, library=lib, version=ver, license=m.get("license", "UNKNOWN"),
            is_direct=is_direct, parent_library=plib, parent_version=pver, used=True,
            version_constraint="*", last_updated=m.get("last_updated", ""), maintainer_count=2,
        ))

    # Direct deps -> app edge.
    for r in sbom_rows:
        if r.get("dependency_type") == "direct":
            emit(r["application_id"], APP_PARENT, "", r["library"], r["version"], True)

    # Transitive edges: authoritative json + the sbom transitive_deps column.
    for e in json.loads(_read(d / "transitive_dependencies.json")):
        emit(e["application_id"], e["parent_library"], e["parent_version"],
             e["child_library"], e["child_version"], False)
    for r in sbom_rows:
        for clib, cver in _parse_children(r.get("transitive_deps", "")):
            emit(r["application_id"], r["library"], r["version"], clib, cver, False)

    # Any transitive sbom row not yet a node -> attach to its app so it's still analyzed.
    child_nodes = {(dp.app_id, dp.library, dp.version) for dp in deps}
    for r in sbom_rows:
        if r.get("dependency_type") == "transitive":
            k = (r["application_id"], r["library"], r["version"])
            if k not in child_nodes:
                emit(r["application_id"], APP_PARENT, "", r["library"], r["version"], False)

    return Dataset(
        applications=_apps(d), dependencies=deps, vulnerabilities=_vulns(d),
        license_rules=_rules(d), labels=_labels(d),
    )
