from backend.app.analysis import build_context


def test_metrics_hit_targets():
    m = build_context().result.metrics
    assert m["vuln_detection"]["recall"] >= 0.85
    assert m["transitive_resolution"]["recall"] >= 0.99
    assert m["license_detection"]["recall"] >= 0.90
    assert m["false_positive_rate"]["reachability_aware"] < 0.20


def test_reachability_suppresses_false_positives():
    m = build_context().result.metrics
    fp = m["false_positive_rate"]
    assert fp["naive"] > fp["reachability_aware"]
    assert fp["suppressed"] > 0


def test_noise_reduction_story():
    nr = build_context().result.metrics["noise_reduction"]
    # Reachability raises vulnerability-alert precision and cuts alert volume.
    assert nr["vuln_precision_reachable"] > nr["vuln_precision_naive"]
    assert nr["vuln_precision_reachable"] == 1.0
    assert nr["alert_reduction"] > 0.20
    assert nr["suppressed_vuln_alerts"] >= 5
