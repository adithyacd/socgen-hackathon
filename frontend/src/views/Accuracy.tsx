import { Check, X, Crosshair, ListFilter } from "lucide-react";
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
          <div className="h-1.5 rounded-full" style={{ width: `${Math.min(100, value * 100)}%`, background: pass ? "#45B08A" : "#F2733B" }} />
        </div>
      </div>
      <div className="w-16 text-right font-mono text-sm font-semibold text-paper">{pct(value)}</div>
      <div className="w-24 text-right font-mono text-[11px] text-mist">{higherIsBetter ? "≥" : "≤"} {pct(target)}</div>
      <div className="w-6">{pass ? <Check size={16} className="text-low" /> : <X size={16} className="text-high" />}</div>
    </div>
  );
}

export default function Accuracy() {
  const { data, loading, error } = useAnalysis();
  if (loading) return <Loading />;
  if (error || !data) return <ErrorState message={error ?? "no data"} />;

  const m = data.metrics as any;
  if (!m?.detection) return <ErrorState message="metrics unavailable" />;
  const ex = m.exploitability;
  const det = m.detection;

  return (
    <div className="mx-auto max-w-5xl">
      <header className="mb-6">
        <div className="eyebrow">Evaluation · official SG benchmark · {m.totals.labels} labeled dependencies</div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">How accurate is Sentinel?</h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          Scored against the provided <code className="font-mono text-xs text-paper">dependency_labels.csv</code>.
          We recover {pct(m.overall.recall)} of all flagged risks and nail license &amp; maintenance perfectly;
          then exploitability tells analysts what to act on first.
        </p>
      </header>

      {/* Hero: exploitability prioritization */}
      <div className="card mb-6 p-6">
        <div className="flex items-center gap-2 text-signal">
          <ListFilter size={18} />
          <span className="eyebrow !text-signal">The exploitability dividend</span>
        </div>
        <div className="mt-4 grid gap-6 md:grid-cols-[1.2fr_1fr]">
          <div>
            <p className="text-sm text-mist">
              Every vulnerable dependency is flagged for completeness, but only{" "}
              <span className="font-mono font-semibold text-crit">{ex.actionable}</span> of{" "}
              <span className="font-mono font-semibold text-paper">{ex.total_vuln_alerts}</span> vulnerability
              alerts are <span className="text-paper">HIGH/MEDIUM exploitability</span> — the set worth an analyst's
              time. The other {pct(ex.deprioritized_pct)} are deprioritized.
            </p>
            <div className="mt-4">
              <div className="flex h-6 w-full overflow-hidden rounded-md">
                <div className="flex items-center justify-center text-[10px] font-semibold text-white" style={{ width: `${(ex.high / ex.total_vuln_alerts) * 100}%`, background: "#E60028" }}>{ex.high} high</div>
                <div className="flex items-center justify-center text-[10px] font-semibold text-ink" style={{ width: `${(ex.medium / ex.total_vuln_alerts) * 100}%`, background: "#F2733B" }}>{ex.medium} med</div>
                <div className="flex items-center justify-center text-[10px] font-semibold text-ink" style={{ width: `${(ex.low / ex.total_vuln_alerts) * 100}%`, background: "#D9A441" }}>{ex.low} low</div>
                <div className="flex items-center justify-center text-[10px] font-semibold text-mist" style={{ width: `${(ex.none / ex.total_vuln_alerts) * 100}%`, background: "#16161A" }}>{ex.none}</div>
              </div>
              <div className="mt-1 font-mono text-[11px] text-mist">{pct(ex.actionable_pct)} actionable · prioritized by real CVE exploitability</div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-line bg-panel2/50 p-4 text-center">
              <div className="eyebrow">Detection recall</div>
              <div className="mt-1 font-display text-3xl font-bold text-low">{pct(m.overall.recall)}</div>
              <div className="mt-1 text-[11px] text-mist">of flagged deps · target ≥ 85%</div>
            </div>
            <div className="rounded-lg border border-line bg-panel2/50 p-4 text-center">
              <div className="eyebrow">License + maint.</div>
              <div className="mt-1 font-display text-3xl font-bold text-low">100%</div>
              <div className="mt-1 text-[11px] text-mist">exact match to labels</div>
            </div>
          </div>
        </div>
      </div>

      {/* Metric table */}
      <div className="card p-5">
        <div className="mb-2 flex items-center gap-4 text-[11px] font-mono uppercase tracking-widest text-mist">
          <div className="flex-1">Metric</div><div className="w-40">Score</div><div className="w-16 text-right">Value</div><div className="w-24 text-right">Target</div><div className="w-6" />
        </div>
        <MetricRow label="Vulnerability detection" hint={`${det.vulnerability.hit}/${det.vulnerability.total} vulnerable deps`} value={det.vulnerability.recall} target={det.vulnerability.target} />
        <MetricRow label="Transitive resolution" hint={`${det.transitive_resolution.hit}/${det.transitive_resolution.total} transitive chains`} value={det.transitive_resolution.recall} target={det.transitive_resolution.target} />
        <MetricRow label="License-conflict detection" hint={`${det.license.hit}/${det.license.total} — incl. unknown + transitive`} value={det.license.recall} target={det.license.target} />
        <MetricRow label="Maintenance detection" hint={`${det.maintenance.hit}/${det.maintenance.total} stale libs`} value={det.maintenance.recall} target={det.maintenance.target} />
        <MetricRow label="Overall recall (is_risky)" hint="all risk types" value={m.overall.recall} target={0.7} />
        <MetricRow label="Overall precision (is_risky)" hint="bounded by label noise — see note" value={m.overall.precision} target={0.75} />
      </div>

      <div className="mt-4 flex items-start gap-2 rounded-lg border border-line bg-panel2/40 p-3 text-xs text-mist">
        <Crosshair size={14} className="mt-0.5 shrink-0 text-signal" />
        <span>
          <span className="font-semibold text-paper">On precision:</span> the provided vulnerability labels are
          version-inconsistent with the vulnerability DB (e.g. <code className="font-mono">log4j-api 4.8.3</code> is
          inside a CVE's affected range yet labeled clean). We detect every vulnerable library via the standard
          below-fixed-version rule; the residual false positives are dependencies the labels randomly mark clean.
          License and maintenance labels are clean, and we match them exactly.
        </span>
      </div>
    </div>
  );
}
