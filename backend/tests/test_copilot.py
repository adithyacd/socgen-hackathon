from backend.app.analysis import build_context
from backend.app.copilot.query import answer, parse_rule_based
from backend.app.narratives.incident import incident_brief
from backend.app.warroom import war_room_impact
from backend.app.config import settings
SYNTH = settings.data_dir  # synthetic dataset (official is default)


def test_rule_parser_maps_keywords():
    spec = parse_rule_based("Which internet-facing apps have exploitable criticals?")
    assert spec.entity == "apps"
    assert spec.internet_facing is True
    assert spec.reachable is True
    assert spec.severity == "critical"


def test_answer_is_grounded_in_real_data():
    ctx = build_context(SYNTH)
    a = answer(ctx, "Show all GPL license conflicts")
    assert a.match_count > 0
    assert all(m.get("app") for m in a.matches)
    # GPL/AGPL libs only.
    libs = {m["library"] for m in a.matches}
    assert libs <= {"chart-lib", "analytics-widget", "report-engine"}


def test_log4shell_question_finds_four_apps():
    ctx = build_context(SYNTH)
    a = answer(ctx, "Which apps are exposed to Log4Shell?")
    assert a.query.get("library") == "log4j"
    assert a.match_count == 4


def test_incident_brief_mentions_cve_and_action():
    ctx = build_context(SYNTH)
    brief = incident_brief(war_room_impact(ctx, "CVE-2021-44228"))
    assert "CVE-2021-44228" in brief
    assert "log4j-core" in brief
    assert "2.17.1" in brief
