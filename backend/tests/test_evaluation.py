from backend.app.analysis import build_context

# build_context() with no args uses the official benchmark dataset (default).


def test_official_benchmark_shape():
    m = build_context().result.metrics
    assert m["available"] is True
    assert m["totals"]["labels"] == 500
    assert set(m["detection"]) == {"vulnerability", "transitive_resolution", "license", "maintenance"}


def test_recall_targets_met():
    m = build_context().result.metrics
    # Recall targets we can hit against their labels.
    assert m["overall"]["recall"] >= 0.85
    assert m["detection"]["license"]["recall"] >= 0.90
    assert m["detection"]["maintenance"]["recall"] >= 0.90
    assert m["detection"]["vulnerability"]["recall"] >= 0.80


def test_exploitability_prioritization():
    ex = build_context().result.metrics["exploitability"]
    assert ex["total_vuln_alerts"] > 0
    assert ex["actionable"] == ex["high"] + ex["medium"]
    assert 0.0 < ex["actionable_pct"] <= 1.0
