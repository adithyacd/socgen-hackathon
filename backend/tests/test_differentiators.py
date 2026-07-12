"""Tests for the four differentiators: threats, audit, SBOM scan, CI gate."""
from backend.app.analysis import build_context
from backend.app.audit import audit_dataset
from backend.cli import evaluate_policy, DEFAULT_POLICY
from backend.app.engines.malicious import scan_threats
from backend.app.scan import parse_manifest, scan_manifest

SAMPLE = """{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "components": [
    {"type":"library","name":"lodash","version":"4.17.21","licenses":[{"license":{"id":"MIT"}}]},
    {"type":"library","name":"requsts","version":"2.28.0","licenses":[{"license":{"id":"MIT"}}]},
    {"type":"library","name":"lodahs","version":"1.0.0","licenses":[{"license":{"id":"MIT"}}]},
    {"type":"library","name":"event-stream","version":"3.3.6","licenses":[{"license":{"id":"MIT"}}]},
    {"type":"library","name":"express","version":"99.0.0","licenses":[{"license":{"id":"MIT"}}]},
    {"type":"library","name":"internal-auth-sdk","version":"5.2.0","licenses":[{"license":{"id":"GPL-3.0"}}]}
  ]
}"""


def _base():
    return build_context().ds


# --- Malicious / threat engine ---
def test_no_false_positive_typosquats_on_official():
    # grpc-go, protobuf-java etc. are legit — must NOT be flagged.
    threats = scan_threats(_base())
    assert not any(t["threat_type"] == "typosquat" for t in threats)


def test_scan_catches_planted_threats():
    r = scan_manifest(SAMPLE, "auto", _base())
    kinds = {(t["threat_type"], t["library"]) for t in r["threats"]}
    assert ("known_malicious", "event-stream") in kinds
    assert ("typosquat", "requsts") in kinds     # 1 deletion from 'requests'
    assert ("typosquat", "lodahs") in kinds      # transposition of 'lodash'
    assert ("dependency_confusion", "express") in kinds  # inflated v99


# --- SBOM parsers ---
def test_parsers():
    assert parse_manifest('{"dependencies":{"react":"^18.2.0"}}', "package.json")[0] == \
        {"library": "react", "version": "18.2.0", "license": "UNKNOWN"}
    assert parse_manifest("requests==2.31.0\nflask>=2.0", "requirements.txt")[0]["library"] == "requests"
    cdx = parse_manifest(SAMPLE, "auto")
    assert len(cdx) == 6 and cdx[0]["library"] == "lodash"


# --- Benchmark auditor ---
def test_audit_flags_version_inconsistency():
    a = audit_dataset(_base())
    assert a["integrity_score"] < 100
    assert a["summary"]["version_inconsistent_vuln_labels"] > 0
    assert any("version-inconsistent" in i["issue"] for i in a["issues"])
    assert a["issues"][0]["evidence"]  # concrete evidence present


# --- CI/CD gate ---
def test_gate_fails_on_malicious_and_typosquat():
    r = scan_manifest(SAMPLE, "auto", _base())
    violations = evaluate_policy(r, DEFAULT_POLICY)
    assert violations
    assert any("malicious" in v for v in violations)
    assert any("typosquat" in v for v in violations)


def test_gate_passes_clean_manifest():
    clean = '{"dependencies":{"react":"18.2.0","lodash":"4.17.21"}}'
    r = scan_manifest(clean, "auto", _base())
    violations = evaluate_policy(r, DEFAULT_POLICY)
    assert violations == []
