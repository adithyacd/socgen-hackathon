"""Precompute every API response into static JSON so the dashboard runs fully
client-side (a bulletproof deployed URL), and render a print-ready HTML report.

Writes into frontend/public/ so `vite build` bundles them into dist/.

Run:  python -m backend.tools.build_static
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.analysis import AnalysisContext, build_context  # noqa: E402
from backend.app.config import REPO_ROOT  # noqa: E402
from backend.app.copilot.query import SUGGESTIONS, answer  # noqa: E402
from backend.app.graphview import build_app_graph  # noqa: E402
from backend.app.narratives.incident import incident_brief  # noqa: E402
from backend.app.optimizer import build_fix_plan  # noqa: E402
from backend.app.warroom import notable_cves, war_room_impact  # noqa: E402

PUBLIC = REPO_ROOT / "frontend" / "public"


def _dump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "model_dump_json"):
        path.write_text(obj.model_dump_json(indent=2), encoding="utf-8")
    else:
        path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")


def _band_color(band: str) -> str:
    return {"critical": "#c81e3a", "high": "#c26a12", "medium": "#9a7d10", "low": "#1f8a6d"}.get(band, "#555")


def render_report(ctx: AnalysisContext) -> str:
    r = ctx.result
    m = r.metrics
    nr = m["noise_reduction"]
    rows = "".join(
        f"<tr><td>{a.name}</td><td>{a.business_criticality}</td>"
        f"<td>{'yes' if a.internet_facing else 'no'}</td>"
        f"<td style='color:{_band_color(a.risk_band)};font-weight:700'>{a.risk_score:.0f}</td>"
        f"<td>{a.counts.get('exploitable_criticals', 0)}</td>"
        f"<td>{a.counts.get('vulnerable', 0) + a.counts.get('transitive_vuln', 0)}</td>"
        f"<td>{a.counts.get('license_conflict', 0)}</td>"
        f"<td>{a.counts.get('unmaintained', 0)}</td></tr>"
        for a in r.apps
    )
    plan = build_fix_plan(ctx)
    fixes = "".join(
        f"<tr><td>{u.library}</td><td>&rarr; {u.to_version}</td><td>{u.app_count}</td>"
        f"<td>{len(u.cves_fixed)}</td><td>{u.criticals_removed}</td>"
        f"<td>{'⚠ ' + u.conflicts[0].parent_library if u.conflicts else '—'}</td></tr>"
        for u in plan.recommended[:8]
    )
    log4j = war_room_impact(ctx, "CVE-2021-44228")
    log4j.narrative = incident_brief(log4j)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Sentinel — Supply Chain Risk Report</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; color:#1a2233; margin:0; padding:40px; max-width:900px; margin:0 auto; }}
  h1 {{ font-size:26px; margin:0; }}
  h2 {{ font-size:16px; margin:28px 0 8px; border-bottom:2px solid #E8B23A; padding-bottom:4px; }}
  .sub {{ color:#66708a; font-size:13px; }}
  .grid {{ display:flex; gap:16px; margin:16px 0; }}
  .kpi {{ flex:1; border:1px solid #e2e6ee; border-radius:8px; padding:12px; }}
  .kpi .n {{ font-size:26px; font-weight:800; }}
  .kpi .l {{ font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:#66708a; }}
  table {{ width:100%; border-collapse:collapse; font-size:12.5px; margin-top:6px; }}
  th,td {{ text-align:left; padding:6px 8px; border-bottom:1px solid #eceef4; }}
  th {{ background:#f6f8fc; font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:#66708a; }}
  .brief {{ background:#fbf7ec; border:1px solid #ecdcb0; border-radius:8px; padding:12px; font-size:13px; }}
  .foot {{ margin-top:32px; color:#9aa3b8; font-size:11px; }}
</style></head><body>
  <div style="display:flex;align-items:baseline;justify-content:space-between">
    <h1>Sentinel — Supply Chain Risk Report</h1>
    <span class="sub">Generated {r.generated_at}</span>
  </div>
  <p class="sub">Software Bill of Materials risk across {r.summary.app_count} applications ·
  {r.summary.dependency_count} dependencies analyzed.</p>

  <div class="grid">
    <div class="kpi"><div class="n" style="color:#c81e3a">{r.summary.exploitable_criticals}</div><div class="l">Exploitable criticals</div></div>
    <div class="kpi"><div class="n">{nr['naive_vuln_alerts']}&rarr;{nr['reachable_vuln_alerts']}</div><div class="l">Vuln alerts after reachability</div></div>
    <div class="kpi"><div class="n" style="color:#1f8a6d">{round(nr['alert_reduction']*100)}%</div><div class="l">Alert noise removed</div></div>
    <div class="kpi"><div class="n">{r.summary.highest_risk_app}</div><div class="l">Highest-risk app</div></div>
  </div>

  <h2>Application risk ranking</h2>
  <table><thead><tr><th>Application</th><th>Criticality</th><th>Internet</th><th>Score</th>
    <th>Exploitable</th><th>Vulnerable</th><th>License</th><th>Unmaintained</th></tr></thead>
    <tbody>{rows}</tbody></table>

  <h2>Zero-day exposure — Log4Shell (CVE-2021-44228)</h2>
  <div class="brief">{log4j.narrative}</div>

  <h2>Recommended remediation — cheapest path to safe</h2>
  <table><thead><tr><th>Library</th><th>Upgrade</th><th>Apps fixed</th><th>CVEs</th>
    <th>Criticals</th><th>Conflict</th></tr></thead><tbody>{fixes}</tbody></table>

  <h2>Detection accuracy (vs. ground-truth labels)</h2>
  <table><tbody>
    <tr><td>Vulnerability detection</td><td>{round(m['vuln_detection']['recall']*100)}%</td></tr>
    <tr><td>Transitive resolution</td><td>{round(m['transitive_resolution']['recall']*100)}%</td></tr>
    <tr><td>License-conflict detection</td><td>{round(m['license_detection']['recall']*100)}%</td></tr>
    <tr><td>False-positive rate (naive &rarr; reachability)</td><td>{round(m['false_positive_rate']['naive']*100)}% &rarr; {round(m['false_positive_rate']['reachability_aware']*100)}%</td></tr>
    <tr><td>Vulnerability-alert precision (naive &rarr; reachability)</td><td>{round(nr['vuln_precision_naive']*100)}% &rarr; {round(nr['vuln_precision_reachable']*100)}%</td></tr>
  </tbody></table>

  <p class="foot">Sentinel · Société Générale PSG Hackathon · synthetic dataset · generated by build_static.py</p>
</body></html>"""


def main() -> None:
    ctx = build_context()
    _dump(PUBLIC / "analysis.json", ctx.result)
    for a in ctx.result.apps:
        _dump(PUBLIC / "graphs" / f"{a.app_id}.json", build_app_graph(ctx, a.app_id))
    cves = notable_cves(ctx)
    _dump(PUBLIC / "warroom" / "cves.json", [c.model_dump() for c in cves])
    for c in cves:
        imp = war_room_impact(ctx, c.cve_id)
        imp.narrative = incident_brief(imp)
        _dump(PUBLIC / "warroom" / f"{c.cve_id}.json", imp)
    _dump(PUBLIC / "optimizer.json", build_fix_plan(ctx))
    _dump(PUBLIC / "copilot.json", {q: answer(ctx, q).model_dump() for q in SUGGESTIONS})
    (PUBLIC / "report.html").write_text(render_report(ctx), encoding="utf-8")

    print(f"Static export written to {PUBLIC}")
    print(f"  analysis.json · {len(ctx.result.apps)} graphs · {len(cves)} war-room CVEs · optimizer · copilot")
    print(f"  report.html ({(PUBLIC / 'report.html').stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
