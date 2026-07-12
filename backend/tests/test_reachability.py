from backend.app.analysis import build_context
from backend.app.graphview import build_app_graph
from backend.app.config import settings
SYNTH = settings.data_dir  # synthetic dataset (official is default)


def test_log4j_reachability_split():
    ctx = build_context(SYNTH)
    by_app = {f.app_id: f for f in ctx.findings if f.library == "log4j-core"}
    # Planted: payments (01) + trading (03) exploitable; loan (06) + wiki (09) unreachable.
    assert by_app["APP-01"].is_reachable is True
    assert by_app["APP-03"].is_reachable is True
    assert by_app["APP-06"].is_reachable is False
    assert by_app["APP-09"].is_reachable is False


def test_attack_path_traced_through_logging():
    ctx = build_context(SYNTH)
    f = next(f for f in ctx.findings if f.library == "log4j-core" and f.app_id == "APP-01")
    assert f.is_direct is False  # log4j arrives transitively
    assert f.paths, "expected an attack path"
    chain = f.paths[0]
    assert any("log4j-core@2.14.1" in step for step in chain)
    assert any("enterprise-logging" in step for step in chain)


def test_reachability_lowers_exploitable_count():
    ctx = build_context(SYNTH)
    # 4 apps carry the critical Log4Shell node, but only 2 are reachable.
    log4j = [f for f in ctx.findings if f.library == "log4j-core"]
    assert len(log4j) == 4
    assert sum(1 for f in log4j if f.is_reachable) == 2


def test_app_graph_endpoint_consistency():
    ctx = build_context(SYNTH)
    graph = build_app_graph(ctx, "APP-01")
    assert graph is not None
    assert any(n.kind == "app" for n in graph.nodes)
    assert any(n.library == "log4j-core" for n in graph.nodes)
    ids = {n.id for n in graph.nodes}
    assert all(e.source in ids and e.target in ids for e in graph.edges)
    assert build_app_graph(ctx, "APP-99") is None
