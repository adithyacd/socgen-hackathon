from backend.app.data.loader import load_dataset
from backend.app.graph.builder import build_graph, library_nodes
from backend.app.config import settings
SYNTH = settings.data_dir  # synthetic dataset (official is default)


def test_dataset_loads():
    ds = load_dataset()
    assert len(ds.applications) == 10
    assert len(ds.dependencies) > 250
    assert len(ds.vulnerabilities) == 200
    assert len(ds.license_rules) == 15
    assert len(ds.labels) > 250


def test_graph_builds_and_overlays_vulns():
    ds = load_dataset()
    g = build_graph(ds)
    # Every app has an app node.
    for app in ds.applications:
        assert g.has_node(f"app:{app.app_id}")
    # log4j-core@2.14.1 is present and carries Log4Shell in 4 apps.
    log4j_hits = [
        data for _n, data in g.nodes(data=True)
        if data.get("library") == "log4j-core"
        and "CVE-2021-44228" in [v.cve_id for v in data.get("vulns", [])]
    ]
    assert len(log4j_hits) == 4


def test_pillow_is_patched_not_vulnerable():
    ds = load_dataset()
    g = build_graph(ds)
    for _n, data in g.nodes(data=True):
        if data.get("library") == "pillow":
            assert data["vulns"] == []  # 8.2.0 is patched vs CVE-2021-28957 (<8.2.0)
