from backend.app.analysis import build_context
from backend.app.optimizer import build_fix_plan
from backend.app.config import settings
SYNTH = settings.data_dir  # synthetic dataset (official is default)


def test_plan_ranked_by_risk_removed():
    ctx = build_context(SYNTH)
    plan = build_fix_plan(ctx)
    risks = [u.risk_removed for u in plan.recommended]
    assert risks == sorted(risks, reverse=True)
    assert plan.total_exploitable_findings > 0


def test_shared_library_fixes_many_apps():
    ctx = build_context(SYNTH)
    plan = build_fix_plan(ctx)
    # commons-text (Text4Shell) is present across several apps -> one upgrade, many apps.
    multi = [u for u in plan.recommended if u.app_count >= 3]
    assert multi, "expected at least one upgrade that fixes multiple apps"


def test_log4j_upgrade_flags_diamond_conflict():
    ctx = build_context(SYNTH)
    plan = build_fix_plan(ctx)
    log4j = next((u for u in plan.recommended if u.library == "log4j-core"), None)
    assert log4j is not None
    assert log4j.to_version == "2.17.1"
    assert log4j.conflicts, "upgrading log4j past 2.16 should conflict with enterprise-logging"
    assert any("2.16.0" in c.constraint for c in log4j.conflicts)


def test_criticals_covered_by_full_plan():
    ctx = build_context(SYNTH)
    plan = build_fix_plan(ctx)
    total_fixed = sum(u.criticals_removed for u in plan.recommended)
    assert total_fixed == plan.total_exploitable_criticals
