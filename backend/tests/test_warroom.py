from backend.app.analysis import build_context
from backend.app.warroom import notable_cves, war_room_impact


def test_notable_cves_ranked_kev_first():
    ctx = build_context()
    cves = notable_cves(ctx)
    ids = [c.cve_id for c in cves]
    assert "CVE-2021-44228" in ids
    # KEV entries should rank ahead of non-KEV.
    first_non_kev = next((i for i, c in enumerate(cves) if not c.kev), len(cves))
    last_kev = max((i for i, c in enumerate(cves) if c.kev), default=-1)
    assert last_kev < first_non_kev


def test_log4shell_impact_ranks_exploitable_first():
    ctx = build_context()
    imp = war_room_impact(ctx, "CVE-2021-44228")
    assert imp is not None
    assert imp.affected_count == 4
    assert imp.exploitable_count == 2
    # Exploitable apps sort ahead of unreachable ones.
    reach_flags = [a.is_reachable for a in imp.affected]
    assert reach_flags == sorted(reach_flags, reverse=True)
    # Top app is business-critical and exploitable.
    assert imp.affected[0].is_reachable
    assert imp.affected[0].business_criticality == "critical"


def test_unknown_cve_returns_none():
    ctx = build_context()
    assert war_room_impact(ctx, "CVE-0000-0000") is None
