import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Siren, Zap, ShieldAlert, ShieldCheck, Globe, Timer, Radiation, Sparkles } from "lucide-react";
import { fetchWarRoomCves, fetchWarRoomImpact } from "../api/client";
import type { AppImpact, WarRoomCve, WarRoomImpact } from "../api/types";
import { severityText, SEVERITY_HEX } from "../lib/risk";

function AttackPath({ path }: { path: string[] }) {
  if (!path.length) return null;
  return (
    <div className="mt-2 flex flex-wrap items-center gap-1 font-mono text-[11px]">
      <span className="text-signal">app</span>
      {path.map((step, i) => (
        <span key={i} className="flex items-center gap-1">
          <span className="text-line">→</span>
          <span className={i === path.length - 1 ? "text-crit" : "text-mist"}>{step}</span>
        </span>
      ))}
    </div>
  );
}

function ImpactRow({ a, rank }: { a: AppImpact; rank: number }) {
  return (
    <div className={`rounded-lg border p-3 ${a.is_reachable ? "border-crit/30 bg-crit/5" : "border-line bg-panel2/40"}`}>
      <div className="flex items-center gap-3">
        <span className="font-mono text-xs text-mist">{String(rank).padStart(2, "0")}</span>
        <Link to={`/app/${a.app_id}`} className="font-display font-semibold text-paper hover:text-signal">
          {a.name}
        </Link>
        <span className="chip">{a.business_criticality}</span>
        {a.internet_facing && (
          <span className="chip">
            <Globe size={11} /> internet
          </span>
        )}
        <div className="ml-auto">
          {a.is_reachable ? (
            <span className="inline-flex items-center gap-1 rounded-md bg-crit/15 px-2 py-0.5 text-xs font-semibold text-crit">
              <ShieldAlert size={12} /> Exploitable{a.exploitability ? ` · ${a.exploitability}` : ""}
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded-md bg-panel2 px-2 py-0.5 text-xs font-semibold text-mist">
              <ShieldCheck size={12} /> {a.exploitability ? `${a.exploitability} exploitability` : "Deprioritized"}
            </span>
          )}
        </div>
      </div>
      <AttackPath path={a.path} />
    </div>
  );
}

export default function WarRoom() {
  const [cves, setCves] = useState<WarRoomCve[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [phase, setPhase] = useState<"idle" | "scanning" | "done">("idle");
  const [impact, setImpact] = useState<WarRoomImpact | null>(null);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    fetchWarRoomCves().then(setCves).catch(() => setCves([]));
  }, []);

  async function run(cve: string) {
    if (!cve) return;
    setSelected(cve);
    setPhase("scanning");
    setImpact(null);
    setElapsed(0);
    const start = performance.now();
    const timer = setInterval(() => setElapsed((performance.now() - start) / 1000), 40);
    const [imp] = await Promise.all([
      fetchWarRoomImpact(cve),
      new Promise((r) => setTimeout(r, 900)),
    ]);
    clearInterval(timer);
    setElapsed((performance.now() - start) / 1000);
    setImpact(imp);
    setPhase("done");
  }

  const cve = impact?.cve;

  return (
    <div className="mx-auto max-w-4xl">
      <header className="mb-6">
        <div className="eyebrow flex items-center gap-1.5">
          <Siren size={13} /> Zero-Day War Room
        </div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">
          A new CVE just dropped. Who’s exposed?
        </h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          One query fans out across the whole portfolio — which apps carry the vulnerable
          library, through which transitive path, and which are actually exploitable.
        </p>
      </header>

      <div className="card mb-6 flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
        <button
          onClick={() => cves[0] && run(cves[0].cve_id)}
          disabled={!cves.length}
          className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-crit px-4 py-2.5 font-display font-semibold text-white transition-transform hover:scale-[1.02] focus:outline-none focus-visible:ring-2 focus-visible:ring-crit disabled:opacity-50"
        >
          <Zap size={18} /> Simulate top zero-day
        </button>
        <span className="hidden text-xs text-mist sm:inline">or</span>
        <select
          value={selected}
          onChange={(e) => run(e.target.value)}
          className="min-w-0 flex-1 rounded-lg border border-line bg-panel2 px-3 py-2.5 font-mono text-sm text-paper focus:outline-none focus-visible:ring-2 focus-visible:ring-signal"
        >
          <option value="">Pick any CVE in the portfolio…</option>
          {cves.map((c) => (
            <option key={c.cve_id} value={c.cve_id}>
              {c.cve_id} · {c.affected_library} · {c.severity} ({c.exploitable_apps} exploitable)
            </option>
          ))}
        </select>
      </div>

      {phase === "scanning" && (
        <div className="card grid place-items-center p-12">
          <div className="flex flex-col items-center gap-3 text-mist">
            <Radiation className="animate-spin text-crit" size={32} />
            <span className="font-mono text-sm">Scanning {cves.reduce((n, c) => n + c.affected_apps, 0) || ""} exposures across the portfolio…</span>
            <span className="font-mono text-2xl font-bold text-paper">{elapsed.toFixed(1)}s</span>
          </div>
        </div>
      )}

      {phase === "done" && impact && cve && (
        <div className="space-y-4">
          {/* CVE header */}
          <div className="card p-5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-lg font-bold text-paper">{cve.cve_id}</span>
              <span className={`font-mono text-xs font-bold ${severityText[cve.severity]}`}>
                {cve.severity.toUpperCase()} · CVSS {cve.cvss}
              </span>
              {cve.kev && (
                <span className="rounded-md bg-crit/15 px-2 py-0.5 text-xs font-semibold text-crit">
                  CISA KEV
                </span>
              )}
              <span className="chip">EPSS {Math.round(cve.epss * 100)}%</span>
              <span className="ml-auto font-mono text-xs text-mist">
                {cve.affected_library} → fix: {cve.fixed_version ?? "n/a"}
              </span>
            </div>
            <p className="mt-2 text-sm text-mist">{cve.description}</p>
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-signal/30 bg-signal/5 px-3 py-2">
              <Timer size={15} className="text-signal" />
              <span className="font-mono text-xs text-paper">
                Portfolio resolved in {elapsed.toFixed(1)}s
              </span>
              <span className="font-mono text-xs text-mist">· manual tracing ≈ 40 hours</span>
            </div>
            {impact.narrative && (
              <div className="mt-3 rounded-lg border border-line bg-panel2/50 p-3">
                <div className="eyebrow mb-1 flex items-center gap-1">
                  <Sparkles size={12} /> Incident brief
                </div>
                <p className="text-sm leading-relaxed text-paper">{impact.narrative}</p>
              </div>
            )}
          </div>

          {/* Blast radius */}
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="card p-4 text-center">
              <div className="eyebrow">Apps affected</div>
              <div className="mt-1 font-display text-3xl font-bold text-paper">{impact.affected_count}</div>
            </div>
            <div className="card p-4 text-center">
              <div className="eyebrow">Exploitable</div>
              <div className="mt-1 font-display text-3xl font-bold" style={{ color: SEVERITY_HEX.critical }}>
                {impact.exploitable_count}
              </div>
            </div>
            <div className="card p-4 text-center">
              <div className="eyebrow">Suppressed</div>
              <div className="mt-1 font-display text-3xl font-bold text-low">
                {impact.affected_count - impact.exploitable_count}
              </div>
            </div>
          </div>
          <div className="rounded-lg border border-crit/30 bg-crit/5 px-4 py-3 text-sm text-paper">
            <span className="font-semibold text-crit">Blast radius: </span>
            {impact.blast_radius}
          </div>

          {/* Ranked affected apps */}
          <div>
            <div className="eyebrow mb-2">Affected applications — exploitable first</div>
            <div className="space-y-2">
              {impact.affected.map((a, i) => (
                <ImpactRow key={a.app_id} a={a} rank={i + 1} />
              ))}
            </div>
          </div>
        </div>
      )}

      {phase === "idle" && (
        <div className="card grid place-items-center p-12 text-center">
          <Siren className="text-mist/40" size={40} />
          <p className="mt-3 max-w-sm text-sm text-mist">
            Hit <span className="font-semibold text-crit">Simulate top zero-day</span> to watch Sentinel
            trace the blast radius across every application in seconds.
          </p>
        </div>
      )}
    </div>
  );
}
