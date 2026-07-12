import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ShieldAlert, ShieldCheck, GitFork } from "lucide-react";
import { fetchAppGraph } from "../api/client";
import type { AppGraph, Finding, GraphNode } from "../api/types";
import { Loading, ErrorState } from "../components/States";
import DependencyGraph from "../components/DependencyGraph";
import RiskMeter from "../components/RiskMeter";
import { SEVERITY_HEX, RISK_TYPE_LABEL, severityText, EXPLOIT_HEX } from "../lib/risk";

const LEGEND = [
  { c: SEVERITY_HEX.critical, label: "Critical" },
  { c: SEVERITY_HEX.high, label: "High" },
  { c: SEVERITY_HEX.medium, label: "Medium" },
  { c: "#79808F", label: "License" },
  { c: "#4A4A52", label: "Unmaintained" },
  { c: "#16161A", label: "Clean" },
];

function ReachBadge({ reachable, exploitability }: { reachable: boolean | null; exploitability?: string }) {
  if (exploitability) {
    const hex = EXPLOIT_HEX[exploitability] ?? "#8A8A93";
    return (
      <span className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold" style={{ background: `${hex}1a`, color: hex }}>
        <ShieldAlert size={12} /> {exploitability.toUpperCase()} exploitability
      </span>
    );
  }
  if (reachable === null) return null;
  return reachable ? (
    <span className="inline-flex items-center gap-1 rounded-md bg-crit/15 px-2 py-0.5 text-xs font-semibold text-crit">
      <ShieldAlert size={12} /> Exploitable
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-md bg-panel2 px-2 py-0.5 text-xs font-semibold text-mist">
      <ShieldCheck size={12} /> Unreachable
    </span>
  );
}

function NodeDetails({ node, finding }: { node: GraphNode; finding?: Finding }) {
  return (
    <div>
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-display text-lg font-semibold text-paper">{node.library}</h3>
        {node.severity && (
          <span className={`font-mono text-xs font-semibold ${severityText[node.severity]}`}>
            {node.severity.toUpperCase()}
          </span>
        )}
      </div>
      <div className="mt-0.5 font-mono text-[11px] text-mist">
        v{node.version} · {node.license || "unknown license"} · {node.is_direct ? "direct" : "transitive"}
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        {node.is_vulnerable && <ReachBadge reachable={node.is_reachable} exploitability={node.exploitability} />}
        {node.risk_types
          .filter((r) => r !== "clean")
          .map((r) => (
            <span key={r} className="chip">
              {RISK_TYPE_LABEL[r as keyof typeof RISK_TYPE_LABEL] ?? r}
            </span>
          ))}
      </div>

      {node.cve_ids.length > 0 && (
        <div className="mt-3">
          <div className="eyebrow">CVEs</div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {node.cve_ids.map((c) => (
              <span key={c} className="rounded bg-panel2 px-1.5 py-0.5 font-mono text-[11px] text-crit">
                {c}
              </span>
            ))}
          </div>
        </div>
      )}

      {finding?.paths?.[0]?.length ? (
        <div className="mt-3">
          <div className="eyebrow flex items-center gap-1">
            <GitFork size={12} /> Attack path
          </div>
          <ol className="mt-1.5 space-y-1">
            <li className="font-mono text-[11px] text-signal">{"◆ app"}</li>
            {finding.paths[0].map((step, i) => (
              <li key={i} className="font-mono text-[11px] text-mist">
                <span className="text-line">{"└─"}</span>{" "}
                <span className={i === finding.paths[0].length - 1 ? "text-crit" : "text-paper"}>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      {node.risk_types.includes("unmaintained") && (
        <p className="mt-3 text-xs text-mist">
          Last updated {node.last_updated} · {node.maintainer_count} maintainer(s).
        </p>
      )}
    </div>
  );
}

export default function AppDetail() {
  const { appId } = useParams();
  const [graph, setGraph] = useState<AppGraph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);

  useEffect(() => {
    let alive = true;
    setGraph(null);
    setSelected(null);
    fetchAppGraph(appId!)
      .then((g) => alive && setGraph(g))
      .catch((e) => alive && setError(String(e)));
    return () => {
      alive = false;
    };
  }, [appId]);

  const selectedFinding = useMemo(() => {
    if (!graph || !selected) return undefined;
    return graph.findings.find(
      (f) => f.library === selected.library && f.version === selected.version,
    );
  }, [graph, selected]);

  if (error) return <ErrorState message={error} />;
  if (!graph) return <Loading label="Resolving dependency graph…" />;

  const app = graph.app;
  return (
    <div className="mx-auto max-w-7xl">
      <Link to="/portfolio" className="mb-4 inline-flex items-center gap-1.5 text-sm text-mist hover:text-paper">
        <ArrowLeft size={15} /> Portfolio
      </Link>

      <header className="mb-4 flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="eyebrow">{app.owner} · {app.environment} · {app.ecosystem}</div>
          <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">{app.name}</h1>
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            <span className="chip">{app.business_criticality}</span>
            <span className="chip">{app.internet_facing ? "internet-facing" : "internal"}</span>
            <span className="chip">{app.dependency_count} deps · {app.direct_count} direct</span>
            {(app.counts.exploitable_criticals ?? 0) > 0 && (
              <span className="inline-flex items-center gap-1 rounded-md bg-crit/15 px-2 py-0.5 font-semibold text-crit">
                <ShieldAlert size={12} /> {app.counts.exploitable_criticals} exploitable critical
              </span>
            )}
          </div>
        </div>
        <div className="w-56">
          <RiskMeter score={app.risk_score} band={app.risk_band} />
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
        <div className="card relative overflow-hidden" style={{ height: "min(70vh, 620px)" }}>
          <div className="absolute left-3 top-3 z-10 flex flex-wrap gap-2 rounded-lg border border-line bg-ink/70 px-3 py-2 backdrop-blur">
            {LEGEND.map((l) => (
              <span key={l.label} className="inline-flex items-center gap-1.5 text-[11px] text-mist">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: l.c }} />
                {l.label}
              </span>
            ))}
          </div>
          <div className="absolute bottom-3 left-3 z-10 font-mono text-[10px] text-mist/70">
            click a node to trace its path · dimmed = lower-exploitability
          </div>
          <DependencyGraph graph={graph} onSelect={setSelected} />
        </div>

        <aside className="card min-h-[300px] p-4">
          {selected ? (
            <NodeDetails node={selected} finding={selectedFinding} />
          ) : (
            <div>
              <div className="eyebrow">Top findings</div>
              <p className="mt-1 text-xs text-mist">Click any node to trace its attack path.</p>
              <ul className="mt-3 space-y-2">
                {graph.findings.slice(0, 8).map((f, i) => (
                  <li key={i} className="rounded-lg border border-line bg-panel2/50 p-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-paper">{f.library}</span>
                      <span className={`font-mono text-[10px] font-semibold ${severityText[f.severity]}`}>
                        {f.severity}
                      </span>
                    </div>
                    <div className="mt-0.5 flex items-center justify-between">
                      <span className="text-[11px] text-mist">
                        {RISK_TYPE_LABEL[f.risk_type as keyof typeof RISK_TYPE_LABEL]}
                      </span>
                      {f.risk_type.includes("vuln") && <ReachBadge reachable={f.is_reachable} exploitability={f.exploitability} />}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
