from backend.app.analysis import build_context


def test_license_conflicts_detected():
    ctx = build_context()
    libs = {f.library for f in ctx.findings if f.risk_type == "license_conflict"}
    # GPL/AGPL copyleft in proprietary/commercial apps.
    assert "report-engine" in libs   # AGPL-3.0
    assert "chart-lib" in libs        # GPL-2.0
    assert "analytics-widget" in libs  # GPL-3.0


def test_maintenance_flags_single_maintainer_or_old():
    ctx = build_context()
    stale = [f for f in ctx.findings if f.risk_type == "unmaintained"]
    assert stale, "expected some unmaintained findings"
    assert all(f.severity == "medium" for f in stale)


def test_findings_merged_one_per_node():
    ctx = build_context()
    keys = [(f.app_id, f.library, f.version) for f in ctx.findings]
    assert len(keys) == len(set(keys)), "each dependency should have one merged finding"


def test_compounding_risk_kept_as_secondary():
    ctx = build_context()
    # Some vulnerable libs are also old; the merge keeps the extra type on secondary_risks.
    compound = [f for f in ctx.findings if f.secondary_risks]
    assert compound, "expected at least one dependency with compounding risk"
