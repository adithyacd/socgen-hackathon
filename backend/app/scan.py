"""Real SBOM / manifest ingestion — turn Sentinel from a demo into a tool.

Parses CycloneDX, SPDX, package.json and requirements.txt, then runs the SAME engines
(vulnerability, license, maintenance) plus the supply-chain threat scan on the uploaded
dependencies. License + typosquat/malicious detection work on any real manifest.
"""
from __future__ import annotations

import json
import re

from .analysis import analyze_dataset
from .engines.malicious import scan_threats
from .models import APP_PARENT, Application, Dataset, Dependency


def _clean_ver(v: str) -> str:
    v = re.sub(r"^[\^~>=<!\s]+", "", (v or "").strip())
    return v.split(",")[0].split(" ")[0].strip() or "0.0.0"


def _detect(content: str) -> str:
    s = content.lstrip()
    if s.startswith("{"):
        try:
            d = json.loads(content)
            if "bomFormat" in d or "components" in d:
                return "cyclonedx"
            if "spdxVersion" in d or "packages" in d:
                return "spdx"
            if any(k in d for k in ("dependencies", "devDependencies", "name")):
                return "package.json"
        except ValueError:
            pass
    return "requirements.txt"


def _cdx_license(c: dict) -> str:
    for l in c.get("licenses", []):
        lic = l.get("license", {}) if isinstance(l, dict) else {}
        return lic.get("id") or lic.get("name") or l.get("expression") or "UNKNOWN"
    return "UNKNOWN"


def parse_manifest(content: str, fmt: str = "auto") -> list[dict]:
    if fmt == "auto":
        fmt = _detect(content)

    if fmt == "package.json":
        data = json.loads(content)
        out = []
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, ver in (data.get(section) or {}).items():
                out.append({"library": name, "version": _clean_ver(ver), "license": "UNKNOWN"})
        return out

    if fmt == "requirements.txt":
        out = []
        for line in content.splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:[=<>!~]+\s*([0-9][^;,\s]*))?", line)
            if m:
                out.append({"library": m.group(1), "version": m.group(2) or "0.0.0", "license": "UNKNOWN"})
        return out

    if fmt == "cyclonedx":
        data = json.loads(content)
        out = [{"library": c.get("name", ""), "version": c.get("version", "0.0.0"),
                "license": _cdx_license(c)} for c in data.get("components", [])]
        return [d for d in out if d["library"]]

    if fmt == "spdx":
        data = json.loads(content)
        out = [{"library": p.get("name", ""), "version": p.get("versionInfo", "0.0.0"),
                "license": p.get("licenseConcluded") or p.get("licenseDeclared") or "UNKNOWN"}
               for p in data.get("packages", [])]
        return [d for d in out if d["library"]]

    raise ValueError(f"Unsupported format: {fmt}")


def scan_manifest(content: str, fmt: str, base: Dataset) -> dict:
    resolved_fmt = _detect(content) if fmt == "auto" else fmt
    parsed = parse_manifest(content, fmt)
    if not parsed:
        return {"error": "No dependencies parsed from the input."}

    app = Application(
        app_id="UPLOAD", name="Uploaded project", business_criticality="high", owner="you",
        internet_facing=True, environment="upload", ecosystem="mixed", license_context="proprietary",
    )
    deps = [Dependency(
        app_id="UPLOAD", library=d["library"], version=d["version"], license=d["license"],
        is_direct=True, parent_library=APP_PARENT, parent_version="", used=True,
        version_constraint="*", last_updated="", maintainer_count=2,
    ) for d in parsed]
    ds = Dataset(applications=[app], dependencies=deps, vulnerabilities=base.vulnerabilities,
                 license_rules=base.license_rules, labels=[])

    ctx = analyze_dataset(ds)
    threats = scan_threats(ds)
    appr = ctx.result.apps[0] if ctx.result.apps else None
    return {
        "format": resolved_fmt,
        "dependency_count": len(parsed),
        "app": appr.model_dump() if appr else None,
        "findings": [f.model_dump() for f in ctx.findings],
        "threats": threats,
        "summary": {
            "vulnerable": sum(1 for f in ctx.findings if f.risk_type in ("vulnerable", "transitive_vuln")),
            "license": sum(1 for f in ctx.findings if "license" in f.risk_type),
            "unmaintained": sum(1 for f in ctx.findings if f.risk_type == "unmaintained"),
            "threats": len(threats),
        },
    }
