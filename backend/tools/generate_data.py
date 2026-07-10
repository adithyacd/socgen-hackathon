"""Generate Sentinel's synthetic SBOM dataset.

Deterministic (seeded). Produces, under the data dir:
  applications.json, dependencies.csv, vulnerability_db.json,
  license_rules.json, labels.csv

Includes a planted Log4j (CVE-2021-44228) scenario reaching several apps through
different transitive paths, with reachability deliberately varied so the
reachability engine measurably cuts false positives.

Run:  python -m backend.tools.generate_data
"""
from __future__ import annotations

import csv
import json
import random
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

# Allow running as a script (python backend/tools/generate_data.py) or module.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.config import settings  # noqa: E402
from backend.app.util.constants import REFERENCE_DATE  # noqa: E402

RNG = random.Random(42)


def days_ago(years: float) -> str:
    return (REFERENCE_DATE - timedelta(days=int(years * 365))).isoformat()


# --------------------------------------------------------------------------- #
# License rules
# --------------------------------------------------------------------------- #
LICENSE_RULES = [
    {"license": "MIT", "category": "permissive", "incompatible_with": [], "risk_level": "low"},
    {"license": "Apache-2.0", "category": "permissive", "incompatible_with": [], "risk_level": "low"},
    {"license": "BSD-3-Clause", "category": "permissive", "incompatible_with": [], "risk_level": "low"},
    {"license": "ISC", "category": "permissive", "incompatible_with": [], "risk_level": "low"},
    {"license": "MPL-2.0", "category": "weak-copyleft", "incompatible_with": [], "risk_level": "medium"},
    {"license": "LGPL-3.0", "category": "weak-copyleft", "incompatible_with": ["Proprietary-Static"], "risk_level": "medium"},
    {"license": "EPL-2.0", "category": "weak-copyleft", "incompatible_with": [], "risk_level": "medium"},
    {"license": "GPL-2.0", "category": "copyleft", "incompatible_with": ["Proprietary", "Proprietary-Static", "Commercial"], "risk_level": "high"},
    {"license": "GPL-3.0", "category": "copyleft", "incompatible_with": ["Proprietary", "Proprietary-Static", "Commercial"], "risk_level": "high"},
    {"license": "AGPL-3.0", "category": "copyleft", "incompatible_with": ["Proprietary", "Proprietary-Static", "Commercial"], "risk_level": "critical"},
    {"license": "CC0-1.0", "category": "permissive", "incompatible_with": [], "risk_level": "low"},
    {"license": "Unlicense", "category": "permissive", "incompatible_with": [], "risk_level": "low"},
    {"license": "Commercial", "category": "proprietary", "incompatible_with": [], "risk_level": "medium"},
    {"license": "Proprietary", "category": "proprietary", "incompatible_with": [], "risk_level": "medium"},
    {"license": "Unknown", "category": "unknown", "incompatible_with": ["Proprietary", "Commercial"], "risk_level": "medium"},
]
PERMISSIVE = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]


# --------------------------------------------------------------------------- #
# Library universe
# --------------------------------------------------------------------------- #
@dataclass
class Lib:
    name: str
    ecosystem: str
    version: str
    license: str
    maintainer_count: int
    last_updated: str
    children: list[tuple] = field(default_factory=list)  # (child_name, used, constraint)


LIBS: dict[str, Lib] = {}
EDGES: dict[str, list[tuple]] = {}  # parent_name -> [(child_name, used, constraint)]


def add_lib(name, ecosystem, version, license, maintainers, last_updated, children=None):
    LIBS[name] = Lib(name, ecosystem, version, license, maintainers, last_updated)
    EDGES[name] = children or []


# --- Curated Java / maven libraries (the Log4j blast zone) ------------------ #
add_lib("spring-boot-starter", "maven", "2.5.4", "Apache-2.0", 40, days_ago(1.2),
        children=[("spring-core", True, ">=5.0.0,<6.0.0"),
                  ("spring-web", True, ">=5.0.0,<6.0.0"),
                  ("jackson-databind", True, ">=2.9.0,<2.14.0"),
                  ("enterprise-logging", True, ">=1.0.0,<2.0.0")])
add_lib("enterprise-logging", "maven", "1.4.0", "Apache-2.0", 6, days_ago(1.5),
        children=[("log4j-core", True, ">=2.0.0,<2.16.0"),
                  ("slf4j-api", True, ">=1.7.0")])
add_lib("log4j-core", "maven", "2.14.1", "Apache-2.0", 25, days_ago(1.8))
add_lib("slf4j-api", "maven", "1.7.30", "MIT", 12, days_ago(2.4))
add_lib("spring-core", "maven", "5.3.8", "Apache-2.0", 55, days_ago(1.1),
        children=[("commons-logging", True, ">=1.2")])
add_lib("spring-web", "maven", "5.3.8", "Apache-2.0", 55, days_ago(1.1),
        children=[("jackson-databind", True, ">=2.9.0,<2.14.0")])
add_lib("jackson-databind", "maven", "2.12.3", "Apache-2.0", 30, days_ago(1.6),
        children=[("jackson-core", True, ">=2.12.0")])
add_lib("jackson-core", "maven", "2.12.3", "Apache-2.0", 30, days_ago(1.6))
add_lib("commons-logging", "maven", "1.2", "Apache-2.0", 8, days_ago(4.0))
add_lib("snakeyaml", "maven", "1.29", "Apache-2.0", 4, days_ago(2.1))
add_lib("commons-text", "maven", "1.9", "Apache-2.0", 10, days_ago(2.3),
        children=[("commons-lang3", True, ">=3.0.0")])
add_lib("commons-lang3", "maven", "3.12.0", "Apache-2.0", 14, days_ago(1.9))
add_lib("hibernate-core", "maven", "5.4.32", "LGPL-3.0", 35, days_ago(1.7),
        children=[("jboss-logging", True, ">=3.0.0")])
add_lib("jboss-logging", "maven", "3.4.1", "Apache-2.0", 9, days_ago(2.0))
add_lib("bcprov-jdk15on", "maven", "1.68", "MIT", 7, days_ago(2.2))
add_lib("chart-lib", "maven", "2.2.0", "GPL-2.0", 3, days_ago(2.4))  # copyleft in proprietary code

# --- Curated npm libraries -------------------------------------------------- #
add_lib("web-server-kit", "npm", "3.1.0", "MIT", 20, days_ago(1.0),
        children=[("express", True, ">=4.0.0,<5.0.0"),
                  ("ws", True, ">=7.0.0,<8.0.0"),
                  ("log-agent", True, ">=2.0.0")])
add_lib("express", "npm", "4.17.1", "MIT", 25, days_ago(1.3),
        children=[("lodash", True, ">=4.0.0"), ("qs", True, ">=6.0.0")])
add_lib("log-agent", "npm", "2.3.0", "MIT", 3, days_ago(1.4),
        children=[("minimist", True, ">=1.2.0,<1.2.6")])
add_lib("lodash", "npm", "4.17.15", "MIT", 30, days_ago(2.5))
add_lib("minimist", "npm", "1.2.5", "MIT", 5, days_ago(2.6))
add_lib("qs", "npm", "6.10.1", "BSD-3-Clause", 8, days_ago(1.9))
add_lib("ws", "npm", "7.4.5", "MIT", 15, days_ago(1.5))
add_lib("axios", "npm", "0.21.1", "MIT", 22, days_ago(1.7),
        children=[("follow-redirects", True, ">=1.0.0,<1.14.7")])
add_lib("follow-redirects", "npm", "1.14.0", "MIT", 4, days_ago(1.8))
add_lib("moment", "npm", "2.29.1", "MIT", 6, days_ago(3.1))
add_lib("ejs", "npm", "3.1.6", "Apache-2.0", 5, days_ago(2.0))
add_lib("node-fetch", "npm", "2.6.1", "MIT", 9, days_ago(2.2))
add_lib("tar", "npm", "6.1.0", "ISC", 7, days_ago(1.6))
add_lib("analytics-widget", "npm", "1.2.0", "GPL-3.0", 2, days_ago(2.8))

# --- Curated pypi libraries ------------------------------------------------- #
add_lib("web-toolkit", "pypi", "2.0.0", "BSD-3-Clause", 18, days_ago(1.1),
        children=[("flask", True, ">=2.0.0"), ("requests", True, ">=2.20.0"),
                  ("report-engine", True, ">=1.0.0")])
add_lib("flask", "pypi", "2.0.1", "BSD-3-Clause", 20, days_ago(1.4),
        children=[("jinja2", True, ">=3.0.0"), ("werkzeug", True, ">=2.0.0")])
add_lib("jinja2", "pypi", "3.0.1", "BSD-3-Clause", 15, days_ago(1.5))
add_lib("werkzeug", "pypi", "2.0.1", "BSD-3-Clause", 15, days_ago(1.5))
add_lib("requests", "pypi", "2.25.1", "Apache-2.0", 28, days_ago(1.9),
        children=[("urllib3", True, ">=1.26.0,<1.26.5"), ("certifi", True, ">=2020.0.0")])
add_lib("urllib3", "pypi", "1.26.4", "MIT", 16, days_ago(1.8))
add_lib("certifi", "pypi", "2021.5.30", "MPL-2.0", 6, days_ago(1.7))
add_lib("report-engine", "pypi", "1.1.0", "AGPL-3.0", 2, days_ago(2.7),
        children=[("pyyaml", False, ">=5.0.0")])
add_lib("pyyaml", "pypi", "5.3.1", "MIT", 8, days_ago(2.9))
add_lib("cryptography", "pypi", "3.4.7", "Apache-2.0", 24, days_ago(1.6))
add_lib("pillow", "pypi", "8.2.0", "HPND", 10, days_ago(2.1))
add_lib("numpy", "pypi", "1.20.3", "BSD-3-Clause", 40, days_ago(1.3))

# HPND isn't in the rules table on purpose -> exercises "Unknown" handling.
LICENSE_NAMES = {r["license"] for r in LICENSE_RULES}


def _filler_libs(n: int) -> None:
    """Pad the universe with low-risk filler libraries for realistic volume."""
    words = ["core", "utils", "common", "io", "net", "codec", "cache", "config",
             "metrics", "json", "http", "crypto", "text", "math", "time", "async",
             "pool", "queue", "stream", "proto", "schema", "auth", "session",
             "template", "parser", "logger", "client", "server", "model", "store"]
    ecosystems = ["maven", "npm", "pypi"]
    for i in range(n):
        eco = ecosystems[i % 3]
        name = f"{eco[:2]}-{RNG.choice(words)}-{i}"
        stale = RNG.random() < 0.18
        add_lib(
            name, eco,
            version=f"{RNG.randint(1, 6)}.{RNG.randint(0, 12)}.{RNG.randint(0, 9)}",
            license=RNG.choice(PERMISSIVE) if RNG.random() < 0.85 else RNG.choice(["MPL-2.0", "Unlicense", "CC0-1.0"]),
            maintainers=1 if stale and RNG.random() < 0.6 else RNG.randint(2, 20),
            last_updated=days_ago(RNG.uniform(2.2, 5.5)) if stale else days_ago(RNG.uniform(0.2, 1.9)),
        )


_filler_libs(70)
FILLER = [n for n in LIBS if n.startswith(("ma-", "np-", "py-"))]


# --------------------------------------------------------------------------- #
# Vulnerabilities
# --------------------------------------------------------------------------- #
def _sev(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


CURATED_VULNS = [
    # The headliner.
    dict(cve_id="CVE-2021-44228", affected_library="log4j-core", version_range=">=2.0.0,<2.15.0",
         cvss=10.0, patch_available=True, fixed_version="2.17.1", vulnerable_symbol="JndiLookup.lookup",
         kev=True, epss=0.975, published="2021-12-10",
         description="Log4Shell: JNDI features do not protect against attacker-controlled LDAP endpoints, allowing remote code execution."),
    dict(cve_id="CVE-2020-9488", affected_library="log4j-core", version_range="<2.13.2",
         cvss=3.7, patch_available=True, fixed_version="2.13.2", vulnerable_symbol="SmtpAppender",
         kev=False, epss=0.12, published="2020-04-27",
         description="Improper validation of certificate with host mismatch in SMTP appender."),
    dict(cve_id="CVE-2020-36518", affected_library="jackson-databind", version_range=">=2.0.0,<2.13.2.1",
         cvss=7.5, patch_available=True, fixed_version="2.13.2.1", vulnerable_symbol="BeanDeserializer",
         kev=False, epss=0.44, published="2022-03-11",
         description="Deeply nested JSON causes a denial of service via stack overflow."),
    dict(cve_id="CVE-2022-1471", affected_library="snakeyaml", version_range="<2.0",
         cvss=8.3, patch_available=True, fixed_version="2.0", vulnerable_symbol="Constructor.construct",
         kev=False, epss=0.61, published="2022-12-01",
         description="Unsafe deserialization of YAML content leads to remote code execution."),
    dict(cve_id="CVE-2022-42889", affected_library="commons-text", version_range=">=1.5,<1.10.0",
         cvss=9.8, patch_available=True, fixed_version="1.10.0", vulnerable_symbol="StringSubstitutor.replace",
         kev=True, epss=0.90, published="2022-10-13",
         description="Text4Shell: variable interpolation allows arbitrary code execution."),
    dict(cve_id="CVE-2021-23337", affected_library="lodash", version_range="<4.17.21",
         cvss=7.2, patch_available=True, fixed_version="4.17.21", vulnerable_symbol="template",
         kev=False, epss=0.33, published="2021-02-15",
         description="Command injection via template function."),
    dict(cve_id="CVE-2021-44906", affected_library="minimist", version_range="<1.2.6",
         cvss=9.8, patch_available=True, fixed_version="1.2.6", vulnerable_symbol="parse",
         kev=False, epss=0.55, published="2022-03-17",
         description="Prototype pollution via crafted arguments."),
    dict(cve_id="CVE-2022-0536", affected_library="follow-redirects", version_range="<1.14.8",
         cvss=6.5, patch_available=True, fixed_version="1.14.8", vulnerable_symbol="Redirect",
         kev=False, epss=0.21, published="2022-02-09",
         description="Exposure of sensitive information via Authorization header leak on redirect."),
    dict(cve_id="CVE-2021-3807", affected_library="ws", version_range=">=7.0.0,<7.4.6",
         cvss=5.3, patch_available=True, fixed_version="7.4.6", vulnerable_symbol="Sender",
         kev=False, epss=0.18, published="2021-09-20",
         description="ReDoS in Sec-WebSocket-Protocol header parsing."),
    dict(cve_id="CVE-2021-33503", affected_library="urllib3", version_range="<1.26.5",
         cvss=7.5, patch_available=True, fixed_version="1.26.5", vulnerable_symbol="parse_url",
         kev=False, epss=0.29, published="2021-06-29",
         description="ReDoS when parsing a URL with many @ characters."),
    dict(cve_id="CVE-2020-14343", affected_library="pyyaml", version_range="<5.4",
         cvss=9.8, patch_available=True, fixed_version="5.4", vulnerable_symbol="load",
         kev=False, epss=0.48, published="2021-02-09",
         description="Arbitrary code execution via full_load / FullLoader bypass."),
    dict(cve_id="CVE-2021-28957", affected_library="pillow", version_range="<8.2.0",
         cvss=5.3, patch_available=True, fixed_version="8.2.0", vulnerable_symbol="ImageColor",
         kev=False, epss=0.14, published="2021-03-21",
         description="Regular expression DoS in ImageColor."),
    dict(cve_id="CVE-2023-0286", affected_library="bcprov-jdk15on", version_range="<1.70",
         cvss=7.4, patch_available=True, fixed_version="1.70", vulnerable_symbol="X400Address",
         kev=False, epss=0.25, published="2023-02-08",
         description="Type confusion in X.400 address processing."),
    dict(cve_id="CVE-2022-25883", affected_library="qs", version_range="<6.10.3",
         cvss=7.5, patch_available=True, fixed_version="6.10.3", vulnerable_symbol="parse",
         kev=False, epss=0.19, published="2023-02-20",
         description="Prototype pollution via crafted query string."),
    dict(cve_id="CVE-2022-24999", affected_library="express", version_range="<4.17.3",
         cvss=7.5, patch_available=True, fixed_version="4.17.3", vulnerable_symbol="qs",
         kev=False, epss=0.22, published="2022-11-26",
         description="DoS via qs prototype pollution reachable through Express."),
]


def _build_vuln_db() -> list[dict]:
    vulns: list[dict] = []
    for v in CURATED_VULNS:
        v = dict(v)
        v["severity"] = _sev(v["cvss"])
        vulns.append(v)
    # Pad with non-matching noise CVEs (target libs/versions not installed).
    idx = 3000
    while len(vulns) < 200:
        idx += 1
        lib = RNG.choice(FILLER + list(LIBS.keys()))
        cvss = round(RNG.uniform(2.0, 9.9), 1)
        # Version range that almost never matches installed versions.
        vulns.append(dict(
            cve_id=f"CVE-2019-{idx}", affected_library=lib,
            version_range="<0.0.1", cvss=cvss, severity=_sev(cvss),
            patch_available=RNG.random() < 0.8, fixed_version="0.0.1",
            vulnerable_symbol="legacyEntry", kev=False,
            epss=round(RNG.uniform(0.0, 0.15), 3), published="2019-05-01",
            description="Historical low-relevance advisory (version not in use)."))
    return vulns


# --------------------------------------------------------------------------- #
# Applications
# --------------------------------------------------------------------------- #
APPS = [
    dict(app_id="APP-01", name="payments-gateway", business_criticality="critical",
         owner="Payments Platform", internet_facing=True, environment="prod",
         ecosystem="maven", license_context="Proprietary", stack="java"),
    dict(app_id="APP-02", name="customer-portal", business_criticality="high",
         owner="Digital Channels", internet_facing=True, environment="prod",
         ecosystem="npm", license_context="Proprietary", stack="node"),
    dict(app_id="APP-03", name="trading-engine", business_criticality="critical",
         owner="Markets Tech", internet_facing=False, environment="prod",
         ecosystem="maven", license_context="Proprietary", stack="java"),
    dict(app_id="APP-04", name="mobile-banking-api", business_criticality="critical",
         owner="Retail Banking", internet_facing=True, environment="prod",
         ecosystem="pypi", license_context="Proprietary", stack="python"),
    dict(app_id="APP-05", name="fraud-detection", business_criticality="high",
         owner="Risk & Fraud", internet_facing=False, environment="prod",
         ecosystem="pypi", license_context="Proprietary", stack="python"),
    dict(app_id="APP-06", name="loan-origination", business_criticality="high",
         owner="Lending", internet_facing=False, environment="prod",
         ecosystem="maven", license_context="Proprietary", stack="java"),
    dict(app_id="APP-07", name="market-data-feed", business_criticality="medium",
         owner="Markets Tech", internet_facing=True, environment="prod",
         ecosystem="npm", license_context="Commercial", stack="node"),
    dict(app_id="APP-08", name="hr-portal", business_criticality="medium",
         owner="People Systems", internet_facing=False, environment="staging",
         ecosystem="pypi", license_context="Proprietary", stack="python"),
    dict(app_id="APP-09", name="internal-wiki", business_criticality="low",
         owner="IT Platform", internet_facing=False, environment="staging",
         ecosystem="maven", license_context="Proprietary", stack="java"),
    dict(app_id="APP-10", name="notifications-service", business_criticality="medium",
         owner="Platform Eng", internet_facing=True, environment="prod",
         ecosystem="npm", license_context="Proprietary", stack="node"),
]

STACK_ROOTS = {
    "java": ["spring-boot-starter", "hibernate-core", "commons-text", "snakeyaml", "bcprov-jdk15on", "chart-lib"],
    "node": ["web-server-kit", "axios", "lodash", "moment", "ejs", "node-fetch", "tar", "analytics-widget"],
    "python": ["web-toolkit", "requests", "cryptography", "pillow", "numpy", "pyyaml"],
}

# Per-app reachability overrides for the planted scenario:
# (app_id, parent_lib, child_lib) -> used
USED_OVERRIDES = {
    ("APP-01", "enterprise-logging", "log4j-core"): True,   # exploitable (critical, internet)
    ("APP-03", "enterprise-logging", "log4j-core"): True,   # exploitable (critical trading)
    ("APP-06", "enterprise-logging", "log4j-core"): False,  # present but UNREACHABLE (FP killer)
    ("APP-09", "enterprise-logging", "log4j-core"): False,  # present but UNREACHABLE (FP killer)
}


def _pick_direct(app: dict) -> list[str]:
    roots = list(STACK_ROOTS[app["stack"]])
    eco = app["ecosystem"]
    filler_pool = [n for n in FILLER if LIBS[n].ecosystem == eco]
    RNG.shuffle(filler_pool)
    n_filler = RNG.randint(14, 22)
    return roots + filler_pool[:n_filler]


# --------------------------------------------------------------------------- #
# Build the dataset
# --------------------------------------------------------------------------- #
from collections import defaultdict  # noqa: E402

from backend.app.util.semver import version_in_range  # noqa: E402
from backend.app.util.staleness import is_stale  # noqa: E402

RULES_BY_LICENSE = {r["license"]: r for r in LICENSE_RULES}


def _matching_cves(library: str, version: str, vuln_by_lib: dict) -> list[dict]:
    return [v for v in vuln_by_lib.get(library, [])
            if version_in_range(version, v["version_range"])]


def _license_conflict(license_name: str, app_license_context: str) -> bool:
    rule = RULES_BY_LICENSE.get(license_name)
    if rule is None:  # unknown license -> treat as the "Unknown" rule
        rule = RULES_BY_LICENSE["Unknown"]
    return app_license_context in rule["incompatible_with"]


def _app_edges(app: dict) -> list[dict]:
    """Expand the app's dependency closure into edge rows."""
    rows: list[dict] = []
    seen_edges: set[tuple] = set()
    queue: list[tuple] = [("__APP__", lib) for lib in _pick_direct(app)]
    while queue:
        parent, lib = queue.pop(0)
        if lib not in LIBS or (parent, lib) in seen_edges:
            continue
        seen_edges.add((parent, lib))
        info = LIBS[lib]
        is_direct = parent == "__APP__"
        if is_direct:
            used, constraint, parent_version = True, "*", ""
        else:
            used, constraint = True, "*"
            for cn, u, c in EDGES.get(parent, []):
                if cn == lib:
                    used, constraint = u, c
                    break
            parent_version = LIBS[parent].version
        key = (app["app_id"], parent, lib)
        if key in USED_OVERRIDES:
            used = USED_OVERRIDES[key]
        rows.append(dict(
            app_id=app["app_id"], library=lib, version=info.version,
            license=info.license, is_direct=is_direct,
            parent_library=parent, parent_version=parent_version,
            used=used, version_constraint=constraint,
            last_updated=info.last_updated, maintainer_count=info.maintainer_count))
        for cn, _u, _c in EDGES.get(lib, []):
            queue.append((lib, cn))
    return rows


def _reachable_nodes(app_id: str, rows: list[dict]) -> set[str]:
    """Nodes reachable from the app over edges where used=True."""
    adj: dict[str, list[str]] = defaultdict(list)
    app_node = f"app:{app_id}"
    for r in rows:
        if not r["used"]:
            continue
        pnode = app_node if r["parent_library"] == "__APP__" else f"{r['parent_library']}@{r['parent_version']}"
        adj[pnode].append(f"{r['library']}@{r['version']}")
    reachable: set[str] = set()
    stack = [app_node]
    while stack:
        n = stack.pop()
        for child in adj.get(n, []):
            if child not in reachable:
                reachable.add(child)
                stack.append(child)
    return reachable


def _label_node(app, library, version, is_direct, license_name, last_updated,
                maintainer_count, cves, reachable) -> dict:
    node = f"{library}@{version}"
    is_reachable = node in reachable
    if cves and is_reachable:
        sev = max((c["severity"] for c in cves),
                  key=lambda s: ["low", "medium", "high", "critical"].index(s))
        return dict(app_id=app["app_id"], library=library, version=version, is_risk=True,
                    risk_type="vulnerable" if is_direct else "transitive_vuln",
                    severity=sev, is_reachable=True,
                    explanation=f"Reachable vulnerable dependency ({', '.join(c['cve_id'] for c in cves)}).")
    if cves and not is_reachable:
        return dict(app_id=app["app_id"], library=library, version=version, is_risk=False,
                    risk_type="clean", severity="low", is_reachable=False,
                    explanation="Vulnerable version present but unreachable (no used path); suppressed.")
    if _license_conflict(license_name, app["license_context"]):
        rule = RULES_BY_LICENSE.get(license_name, RULES_BY_LICENSE["Unknown"])
        return dict(app_id=app["app_id"], library=library, version=version, is_risk=True,
                    risk_type="license_conflict", severity=rule["risk_level"], is_reachable=is_reachable,
                    explanation=f"License '{license_name}' incompatible with {app['license_context']} context.")
    if is_stale(last_updated, maintainer_count):
        return dict(app_id=app["app_id"], library=library, version=version, is_risk=True,
                    risk_type="unmaintained", severity="medium", is_reachable=is_reachable,
                    explanation=f"Unmaintained: last updated {last_updated}, {maintainer_count} maintainer(s).")
    return dict(app_id=app["app_id"], library=library, version=version, is_risk=False,
                risk_type="clean", severity="low", is_reachable=is_reachable,
                explanation="No detected risk.")


def build_dataset():
    vulns = _build_vuln_db()
    vuln_by_lib: dict[str, list[dict]] = defaultdict(list)
    for v in vulns:
        vuln_by_lib[v["affected_library"]].append(v)

    all_rows: list[dict] = []
    all_labels: list[dict] = []
    for app in APPS:
        rows = _app_edges(app)
        all_rows.extend(rows)
        reachable = _reachable_nodes(app["app_id"], rows)
        # One label per unique node in the app.
        nodes: dict[tuple, dict] = {}
        for r in rows:
            nodes.setdefault((r["library"], r["version"]), r)
            if r["is_direct"]:
                nodes[(r["library"], r["version"])] = {**nodes[(r["library"], r["version"])], "is_direct": True}
        for (library, version), r in nodes.items():
            cves = _matching_cves(library, version, vuln_by_lib)
            all_labels.append(_label_node(
                app, library, version, r["is_direct"], r["license"],
                r["last_updated"], r["maintainer_count"], cves, reachable))

    apps_out = [{k: v for k, v in a.items() if k != "stack"} for a in APPS]
    return apps_out, all_rows, vulns, LICENSE_RULES, all_labels


# --------------------------------------------------------------------------- #
# Write + summarise
# --------------------------------------------------------------------------- #
def _write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in fields})


def main() -> None:
    out = settings.data_dir
    out.mkdir(parents=True, exist_ok=True)
    apps, deps, vulns, rules, labels = build_dataset()

    (out / "applications.json").write_text(json.dumps(apps, indent=2), encoding="utf-8")
    (out / "vulnerability_db.json").write_text(json.dumps(vulns, indent=2), encoding="utf-8")
    (out / "license_rules.json").write_text(json.dumps(rules, indent=2), encoding="utf-8")
    _write_csv(out / "dependencies.csv", deps,
               ["app_id", "library", "version", "license", "is_direct",
                "parent_library", "parent_version", "used", "version_constraint",
                "last_updated", "maintainer_count"])
    _write_csv(out / "labels.csv", labels,
               ["app_id", "library", "version", "is_risk", "risk_type",
                "severity", "is_reachable", "explanation"])

    # Summary.
    dist: dict[str, int] = defaultdict(int)
    for lb in labels:
        dist[lb["risk_type"]] += 1
    total = len(labels)
    print(f"Wrote dataset to {out}")
    print(f"  applications: {len(apps)}")
    print(f"  dependency edges: {len(deps)}")
    print(f"  vulnerabilities: {len(vulns)}")
    print(f"  license rules: {len(rules)}")
    print(f"  labels (unique app+library nodes): {total}")
    print("  risk-type mix:")
    for k in ["vulnerable", "transitive_vuln", "license_conflict", "unmaintained", "clean"]:
        print(f"    {k:16s} {dist[k]:4d}  ({100*dist[k]/total:.1f}%)")
    log4j = [lb for lb in labels if lb["library"] == "log4j-core"]
    exploitable = [lb for lb in log4j if lb["is_risk"]]
    print(f"  Log4Shell (CVE-2021-44228): present in {len(log4j)} apps, "
          f"{len(exploitable)} reachable/exploitable, {len(log4j)-len(exploitable)} suppressed by reachability")


if __name__ == "__main__":
    main()
