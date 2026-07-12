import { Link } from "react-router-dom";
import { Boxes, Globe, Lock, ShieldAlert, Zap } from "lucide-react";
import { useAnalysis } from "../lib/analysisContext";
import { Loading, ErrorState } from "../components/States";
import StatTile from "../components/StatTile";
import RiskMeter from "../components/RiskMeter";
import type { AppRisk } from "../api/types";
import { RISK_TYPE_HEX } from "../lib/risk";

const CRIT_HEX = "#E60028";

function CountDot({ color, label, n }: { color: string; label: string; n: number }) {
  return (
    <span className="inline-flex items-center gap-1.5" title={label}>
      <span className="h-2 w-2 rounded-full" style={{ background: color, opacity: n ? 1 : 0.25 }} />
      <span className={`font-mono text-xs ${n ? "text-paper" : "text-mist/50"}`}>{n}</span>
    </span>
  );
}

function AppCard({ app }: { app: AppRisk }) {
  const c = app.counts;
  const exploit = c.exploitable_criticals ?? 0;
  return (
    <Link
      to={`/app/${app.app_id}`}
      className="card group p-5 transition-colors hover:border-signal/40"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-display text-lg font-semibold text-paper group-hover:text-signal">
            {app.name}
          </h3>
          <div className="mt-0.5 font-mono text-[11px] text-mist">
            {app.owner} · {app.environment} · {app.ecosystem}
          </div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span
            className="chip"
            style={{ borderColor: `${CRIT_HEX}44`, color: "#F4F4F5" }}
            title="Business criticality"
          >
            {app.business_criticality}
          </span>
          <span className="chip" title={app.internet_facing ? "Internet-facing" : "Internal"}>
            {app.internet_facing ? <Globe size={12} /> : <Lock size={12} />}
            {app.internet_facing ? "internet" : "internal"}
          </span>
        </div>
      </div>

      <div className="mt-4">
        <RiskMeter score={app.risk_score} band={app.risk_band} />
      </div>

      <div className="mt-4 flex items-center justify-between border-t border-line pt-3">
        <div className="flex items-center gap-3">
          <CountDot color={RISK_TYPE_HEX.vulnerable} label="Vulnerable (direct)" n={c.vulnerable ?? 0} />
          <CountDot color={RISK_TYPE_HEX.transitive_vuln} label="Vulnerable (transitive)" n={c.transitive_vuln ?? 0} />
          <CountDot color={RISK_TYPE_HEX.license_conflict} label="License conflicts" n={c.license_conflict ?? 0} />
          <CountDot color={RISK_TYPE_HEX.unmaintained} label="Unmaintained" n={c.unmaintained ?? 0} />
        </div>
        {exploit > 0 && (
          <span
            className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold"
            style={{ background: `${CRIT_HEX}1a`, color: CRIT_HEX }}
          >
            <Zap size={12} /> {exploit} exploitable
          </span>
        )}
      </div>
      <div className="mt-2 font-mono text-[11px] text-mist">
        {app.dependency_count} dependencies · {app.direct_count} direct
      </div>
    </Link>
  );
}

export default function Portfolio() {
  const { data, loading, error } = useAnalysis();
  if (loading) return <Loading />;
  if (error || !data) return <ErrorState message={error ?? "no data"} />;

  const s = data.summary;
  return (
    <div className="mx-auto max-w-6xl">
      <header className="mb-6">
        <div className="eyebrow">Portfolio · generated {data.generated_at}</div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">
          Supply-chain exposure across {s.app_count} applications
        </h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          Every dependency, resolved through its transitive chain, cross-referenced against
          known vulnerabilities, licenses, and maintenance signals — ranked worst-first.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Applications" value={s.app_count} icon={<Boxes size={16} />} />
        <StatTile
          label="Dependencies analyzed"
          value={s.dependency_count}
          sub="direct + transitive"
        />
        <StatTile
          label="High-priority criticals"
          value={s.exploitable_criticals}
          accent={CRIT_HEX}
          sub="critical + high/med exploitability"
          icon={<ShieldAlert size={16} className="text-crit" />}
        />
        <StatTile label="Highest-risk app" value={s.highest_risk_app} sub="click below to inspect" />
      </div>

      <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {data.apps.map((app) => (
          <AppCard key={app.app_id} app={app} />
        ))}
      </div>
    </div>
  );
}
