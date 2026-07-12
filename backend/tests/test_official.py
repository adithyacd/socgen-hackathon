"""Tests for the official SG benchmark ingestion + classification (default dataset)."""
from backend.app.analysis import build_context
from backend.app.warroom import notable_cves, war_room_impact


def test_official_dataset_loads():
    ctx = build_context()  # official
    assert len(ctx.result.apps) == 10
    assert len(ctx.ds.labels) == 500
    assert len(ctx.ds.dependencies) > 400


def test_official_taxonomy_emitted():
    ctx = build_context()
    types = {f.risk_type for f in ctx.findings}
    assert "vulnerable" in types
    assert "unmaintained" in types
    assert types & {"license_conflict", "license_unknown", "transitive_license_conflict"}


def test_exploitability_carried_on_vulns():
    ctx = build_context()
    vulns = [f for f in ctx.findings if f.risk_type in ("vulnerable", "transitive_vuln")]
    assert vulns
    assert all(f.exploitability in ("high", "medium", "low", "none") for f in vulns)


def test_warroom_top_cve_has_impact():
    ctx = build_context()
    cves = notable_cves(ctx)
    assert cves
    imp = war_room_impact(ctx, cves[0].cve_id)
    assert imp is not None and imp.affected_count >= 1
