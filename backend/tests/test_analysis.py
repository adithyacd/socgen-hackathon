from backend.app.analysis import run_analysis
from backend.app.models import Application, Finding
from backend.app.scoring.score import app_risk_score, risk_band, score_finding
from backend.app.config import settings
SYNTH = settings.data_dir  # synthetic dataset (official is default)


def _app(**kw):
    base = dict(app_id="A", name="a", business_criticality="critical", owner="o",
                internet_facing=True, environment="prod", ecosystem="maven",
                license_context="Proprietary")
    base.update(kw)
    return Application(**base)


def test_critical_scores_higher_than_low():
    crit = Finding(app_id="A", library="x", version="1", is_direct=True,
                   risk_type="vulnerable", severity="critical", kev=True, epss=0.9)
    low = Finding(app_id="A", library="y", version="1", is_direct=False,
                  risk_type="vulnerable", severity="low")
    assert score_finding(crit) > score_finding(low)


def test_unreachable_vuln_scores_far_lower():
    reachable = Finding(app_id="A", library="x", version="1", is_direct=True,
                        risk_type="vulnerable", severity="critical", is_reachable=True)
    unreachable = Finding(app_id="A", library="x", version="1", is_direct=True,
                          risk_type="vulnerable", severity="critical", is_reachable=False)
    assert score_finding(unreachable) < score_finding(reachable) * 0.3


def test_app_score_bounded_and_banded():
    f = Finding(app_id="A", library="x", version="1", is_direct=True,
                risk_type="vulnerable", severity="critical", kev=True, epss=0.9)
    f.score = score_finding(f)
    s = app_risk_score([f], _app())
    assert 0 <= s <= 100
    assert risk_band(s) in ("low", "medium", "high", "critical")


def test_run_analysis_shape():
    result = run_analysis(SYNTH)
    assert result.summary.app_count == 10
    assert len(result.apps) == 10
    # sorted worst-first
    scores = [a.risk_score for a in result.apps]
    assert scores == sorted(scores, reverse=True)
    # every score is valid
    assert all(0 <= a.risk_score <= 100 for a in result.apps)
    # we detected Log4Shell somewhere
    log4j = [f for f in result.findings if f.library == "log4j-core"]
    assert log4j and any("CVE-2021-44228" in f.cve_ids for f in log4j)


def test_highest_risk_is_critical_internet_app():
    result = run_analysis(SYNTH)
    top = result.apps[0]
    # The worst app should be business-critical (payments/trading are the planted hotspots)
    assert top.business_criticality in ("critical", "high")
    assert top.counts["exploitable_criticals"] >= 1
