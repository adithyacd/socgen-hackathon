import { Check, X, TrendingDown } from "lucide-react";
import { useAnalysis } from "../lib/analysisContext";
import { Loading, ErrorState } from "../components/States";

const pct = (x: number) => `${Math.round(x * 100)}%`;

function MetricRow({
  label,
  value,
  target,
  higherIsBetter = true,
  hint,
}: {
  label: string;
  value: number;
  target: number;
  higherIsBetter?: boolean;
  hint?: string;
}) {
  const pass = higherIsBetter ? value >= target : value <= target;
  return (
    <div className="flex items-center gap-4 border-b border-line py-3 last:border-0">
      <div className="flex-1">
        <div className="text-sm font-medium text-paper">{label}</div>
        {hint && <div className="text-xs text-mist">{hint}</div>}
      </div>
      <div className="w-40">
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-panel2">
          <div
            className="h-1.5 rounded-full"
            style={{
              width: `${Math.min(100, value * 100)}%`,
              background: pass ? "#4CC9A0" : "#F2913D",
            }}
          />
        </div>
      </div>
      <div className="w-24 text-right font-mono text-sm font-semibold text-paper">{pct(value)}</div>
      <div className="w-28 text-right font-mono text-[11px] text-mist">
        {higherIsBetter ? "≥" : "≤"} {pct(target)}
      </div>
      <div className="w-6">
        {pass ? <Check size={16} className="text-low" /> : <X size={16} className="text-high" />}
      </div>
    </div>
  );
}

export default function Accuracy() {
  const { data, loading, error } = useAnalysis();
  if (loading) return <Loading />;
  if (error || !data) return <ErrorState message={error ?? "no data"} />;

  const m = data.metrics as any;
  if (!m?.noise_reduction) return <ErrorState message="metrics unavailable" />;
  const nr = m.noise_reduction;
  const reachPct = nr.naive_vuln_alerts ? nr.reachable_vuln_alerts / nr.naive_vuln_alerts : 0;

  return (
    <div className="mx-auto max-w-5xl">
      <header className="mb-6">
        <div className="eyebrow">Evaluation · measured against {m.totals.labels} labeled dependencies</div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">
          How accurate is Sentinel?
        </h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          Every finding is scored against ground-truth labels. Detection is a CVE lookup, so
          recall is complete — the hard, valuable metric is <em>precision</em>: not drowning
          analysts in unexploitable noise.
        </p>
      </header>

      {/* Hero: reachability noise reduction */}
      <div className="card mb-6 overflow-hidden p-6">
        <div className="flex items-center gap-2 text-signal">
          <TrendingDown size={18} />
          <span className="eyebrow !text-signal">The reachability dividend</span>
        </div>
        <div className="mt-4 grid gap-6 md:grid-cols-[1.2fr_1fr]">
          <div>
            <p className="text-sm text-mist">
              A naive scanner raises{" "}
              <span className="font-mono font-semibold text-paper">{nr.naive_vuln_alerts}</span>{" "}
              vulnerability alerts. Reachability analysis shows only{" "}
              <span className="font-mono font-semibold text-low">{nr.reachable_vuln_alerts}</span>{" "}
              are actually exploitable — the other{" "}
              <span className="font-mono font-semibold text-crit">{nr.suppressed_vuln_alerts}</span>{" "}
              are present but never called.
            </p>
            {/* stacked bar */}
            <div className="mt-4">
              <div className="flex h-6 w-full overflow-hidden rounded-md">
                <div
                  className="flex items-center justify-center text-[10px] font-semibold text-ink"
                  style={{ width: `${reachPct * 100}%`, background: "#4CC9A0" }}
                >
                  {nr.reachable_vuln_alerts} exploitable
                </div>
                <div
                  className="flex items-center justify-center text-[10px] font-semibold text-mist"
                  style={{ width: `${(1 - reachPct) * 100}%`, background: "#26324e" }}
                >
                  {nr.suppressed_vuln_alerts} suppressed
                </div>
              </div>
              <div className="mt-1 font-mono text-[11px] text-mist">
                {pct(nr.alert_reduction)} of vulnerability alerts eliminated as noise
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-line bg-panel2/50 p-4 text-center">
              <div className="eyebrow">Alert precision</div>
              <div className="mt-1 font-display text-2xl font-bold text-mist line-through decoration-crit/60">
                {pct(nr.vuln_precision_naive)}
              </div>
              <div className="font-display text-3xl font-bold text-low">
                {pct(nr.vuln_precision_reachable)}
              </div>
              <div className="mt-1 text-[11px] text-mist">naive → reachability</div>
            </div>
            <div className="rounded-lg border border-line bg-panel2/50 p-4 text-center">
              <div className="eyebrow">False-positive rate</div>
              <div className="mt-1 font-display text-2xl font-bold text-mist line-through decoration-crit/60">
                {pct(m.false_positive_rate.naive)}
              </div>
              <div className="font-display text-3xl font-bold text-low">
                {pct(m.false_positive_rate.reachability_aware)}
              </div>
              <div className="mt-1 text-[11px] text-mist">naive → reachability</div>
            </div>
          </div>
        </div>
      </div>

      {/* Metric table */}
      <div className="card p-5">
        <div className="mb-2 flex items-center gap-4 text-[11px] font-mono uppercase tracking-widest text-mist">
          <div className="flex-1">Metric</div>
          <div className="w-40">Score</div>
          <div className="w-24 text-right">Value</div>
          <div className="w-28 text-right">Target</div>
          <div className="w-6" />
        </div>
        <MetricRow label="Vulnerability detection" hint="known CVEs recovered" value={m.vuln_detection.recall} target={m.vuln_detection.target} />
        <MetricRow label="Transitive resolution" hint="nested vulnerable paths resolved" value={m.transitive_resolution.recall} target={m.transitive_resolution.target} />
        <MetricRow label="License-conflict detection" hint="copyleft-in-proprietary flagged" value={m.license_detection.recall} target={m.license_detection.target} />
        <MetricRow label="Maintenance detection" hint="stale / abandoned libs" value={m.maintenance_detection.recall} target={m.maintenance_detection.target} />
        <MetricRow label="Severity agreement" hint="matches labeled severity" value={m.severity_agreement.rate} target={m.severity_agreement.target} />
        <MetricRow label="False-positive rate" hint="lower is better" value={m.false_positive_rate.reachability_aware} target={m.false_positive_rate.target} higherIsBetter={false} />
      </div>
    </div>
  );
}
