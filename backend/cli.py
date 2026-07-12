"""Sentinel CLI — a CI/CD supply-chain gate.

Scans a manifest / SBOM and FAILS the build (non-zero exit) on policy violations, so
supply-chain risk is caught in the pull request, not in a quarterly audit. This is the
developer-facing surface — governance as code, not just a dashboard.

Usage:
    python -m backend.cli <manifest> [--policy sentinel-policy.json] [--format auto] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_POLICY = {
    "fail_on_exploitable_critical": True,
    "fail_on_known_malicious": True,
    "fail_on_typosquat": True,
    "fail_on_dependency_confusion": True,
    "max_license_conflicts": 0,
}


def load_policy(path: str | None) -> dict:
    if path and Path(path).exists():
        return {**DEFAULT_POLICY, **json.loads(Path(path).read_text("utf-8"))}
    return DEFAULT_POLICY


def evaluate_policy(result: dict, policy: dict) -> list[str]:
    findings, threats = result["findings"], result["threats"]
    violations: list[str] = []

    crit = [f for f in findings
            if f["risk_type"] in ("vulnerable", "transitive_vuln") and f["severity"] == "critical"
            and (f.get("exploitability", "") in ("high", "medium", ""))]
    if policy["fail_on_exploitable_critical"] and crit:
        violations.append(f"{len(crit)} exploitable critical vulnerability(ies)")

    mal = [t for t in threats if t["threat_type"] == "known_malicious"]
    if policy["fail_on_known_malicious"] and mal:
        violations.append("known-malicious package(s): " + ", ".join(t["library"] for t in mal))

    typo = [t for t in threats if t["threat_type"] == "typosquat"]
    if policy["fail_on_typosquat"] and typo:
        violations.append("typosquat(s): " + ", ".join(t["library"] for t in typo))

    conf = [t for t in threats if t["threat_type"] == "dependency_confusion"]
    if policy["fail_on_dependency_confusion"] and conf:
        violations.append("dependency-confusion: " + ", ".join(t["library"] for t in conf))

    lic = [f for f in findings if f["risk_type"] in ("license_conflict", "transitive_license_conflict")]
    if len(lic) > policy["max_license_conflicts"]:
        libs = ", ".join(sorted({f["library"] for f in lic}))
        violations.append(f"{len(lic)} license conflict(s) > {policy['max_license_conflicts']}: {libs}")

    return violations


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel", description="Supply-chain risk gate for CI/CD")
    ap.add_argument("manifest", help="package.json / requirements.txt / CycloneDX / SPDX file")
    ap.add_argument("--policy", help="path to sentinel-policy.json")
    ap.add_argument("--format", default="auto")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    from backend.app.analysis import build_context
    from backend.app.scan import scan_manifest

    content = Path(args.manifest).read_text(encoding="utf-8", errors="replace")
    result = scan_manifest(content, args.format, build_context().ds)
    if "error" in result:
        print(result["error"], file=sys.stderr)
        return 2

    policy = load_policy(args.policy)
    violations = evaluate_policy(result, policy)
    s = result["summary"]

    if args.json:
        print(json.dumps({"summary": s, "violations": violations, "passed": not violations}, indent=2))
    else:
        print(f"Sentinel supply-chain gate — {result['dependency_count']} deps ({result['format']})")
        print(f"  vulnerable={s['vulnerable']}  license={s['license']}  threats={s['threats']}")
        if violations:
            print("\nPOLICY VIOLATIONS:")
            for v in violations:
                print(f"  x {v}")
            print("\nGate FAILED.")
        else:
            print("\nGate PASSED.")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
