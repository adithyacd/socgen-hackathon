"""Supply-chain THREAT engine — the risks a CVE list can't see.

Known CVEs are the *known* risk. Real supply-chain attacks — SolarWinds, event-stream,
ua-parser-js, node-ipc, xz-utils — are compromised or impostor packages. This engine
detects three attack classes that the CVE-centric dataset (and most teams) ignore:

  1. Typosquatting          — a name one edit away from a hugely popular package
  2. Dependency confusion   — a public namesake published at an absurd version
  3. Known-malicious        — an exact match to a historical compromise/protestware

These are reported SEPARATELY from the CVE benchmark (the official labels don't cover
them), so they never distort the detection metrics — they add a whole new dimension.
"""
from __future__ import annotations

from ..models import Dataset

# A compact registry of very popular packages across ecosystems (impersonation targets).
POPULAR_PACKAGES = {
    # npm
    "lodash", "react", "react-dom", "express", "axios", "chalk", "commander", "moment",
    "request", "debug", "async", "webpack", "babel-core", "jest", "typescript", "vue",
    "underscore", "colors", "node-fetch", "minimist", "yargs", "uuid", "dotenv", "redux",
    # pypi
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "setuptools", "pip",
    "cryptography", "pyyaml", "jinja2", "click", "boto3", "scipy", "pillow", "certifi",
    "sqlalchemy", "werkzeug", "beautifulsoup4", "pytest", "six", "wheel",
    # maven / java
    "jackson-databind", "guava", "log4j-core", "slf4j-api", "commons-lang3", "gson",
    "spring-core", "netty-all", "commons-io", "junit", "hibernate-core", "commons-codec",
    # go
    "gin", "gorilla-mux", "logrus", "cobra", "testify", "grpc", "protobuf",
}

# Historical malicious / compromised / protestware packages (name, optional bad version).
KNOWN_MALICIOUS = {
    "event-stream": "3.3.6",
    "ua-parser-js": "0.7.29",
    "node-ipc": "10.1.1",     # protestware
    "coa": "2.0.3",
    "rc": "1.3.9",
    "colors": "1.4.44-liberty-2",  # protestware sabotage
    "faker": "6.6.6",
    "flatmap-stream": None,
    "eslint-scope": "3.7.2",
    "left-pad": None,
    "xz": "5.6.0",            # xz-utils backdoor
    "liblzma": "5.6.0",
    "ctx": None,              # pypi hijack
    "phpass": None,
}

# Typosquats are almost always a single edit or a popular name wrapped in an affix.
# Distance 2 catches too many legitimate packages (black, redis, cors), so we require 1.
_MAX_EDIT = 1


def _damerau(a: str, b: str, cap: int = 2) -> int:
    """Damerau-Levenshtein distance (adjacent transposition = 1) — the typosquat metric.
    Covers substitution/insertion/deletion AND transposition (e.g. lodahs -> lodash)."""
    la, lb = len(a), len(b)
    if abs(la - lb) > cap:
        return cap + 1
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        best = cap + 1
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
            best = min(best, d[i][j])
        if best > cap:
            return cap + 1
    return d[la][lb]


def _closest_popular(name: str):
    """Nearest popular package at Damerau distance 1 (precise — avoids flagging legit
    ecosystem names like grpc-go or protobuf-java)."""
    for pop in POPULAR_PACKAGES:
        if pop != name and _damerau(name, pop, cap=1) == 1:
            return pop
    return None


def _major(version: str) -> int:
    try:
        return int(version.split(".")[0])
    except (ValueError, IndexError, AttributeError):
        return 0


def scan_threats(ds: Dataset) -> list[dict]:
    """Return supply-chain threat findings across all dependencies."""
    threats: list[dict] = []
    seen: set[tuple] = set()
    app_name = {a.app_id: a.name for a in ds.applications}

    for dep in ds.dependencies:
        name = dep.library.lower()
        key = (dep.app_id, name, dep.version)
        if key in seen:
            continue
        seen.add(key)

        # 1. Known-malicious / protestware
        if name in KNOWN_MALICIOUS:
            bad = KNOWN_MALICIOUS[name]
            hit = bad is None or bad == dep.version
            if hit:
                threats.append(_t(dep, app_name, "known_malicious", "critical", 0.95,
                                  f"'{dep.library}' matches a known compromised/protestware package"
                                  f"{f' (bad version {bad})' if bad else ''}.", suggested=""))
                continue

        # 2. Dependency confusion — public namesake at an absurdly inflated version
        if name in POPULAR_PACKAGES and _major(dep.version) >= 50:
            threats.append(_t(dep, app_name, "dependency_confusion", "high", 0.7,
                              f"'{dep.library}' is a well-known public package pinned to an "
                              f"implausible version {dep.version} — a classic dependency-confusion signal.",
                              suggested=dep.library))
            continue

        # 3. Typosquatting — one edit (incl. transposition) from a hugely popular package
        if name not in POPULAR_PACKAGES and len(name) >= 4:
            pop = _closest_popular(name)
            if pop:
                threats.append(_t(dep, app_name, "typosquat", "high", 0.85,
                                  f"'{dep.library}' is one edit from the popular package "
                                  f"'{pop}' — likely typosquat.", suggested=pop))
    # Highest confidence first.
    threats.sort(key=lambda t: (-t["confidence"]))
    return threats


def _t(dep, app_name, threat_type, severity, confidence, detail, suggested):
    return {
        "app_id": dep.app_id, "app": app_name.get(dep.app_id, dep.app_id),
        "library": dep.library, "version": dep.version,
        "threat_type": threat_type, "severity": severity,
        "confidence": round(confidence, 2), "detail": detail, "suggested": suggested,
    }
