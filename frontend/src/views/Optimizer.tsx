import { useEffect, useMemo, useState } from "react";
import { Wrench, AlertTriangle, PackageCheck, Boxes } from "lucide-react";
import { fetchFixPlan } from "../api/client";
import type { FixPlan, Upgrade } from "../api/types";
import { Loading, ErrorState } from "../components/States";

function minimalCriticalSet(plan: FixPlan): Set<string> {
  // Greedy: select upgrades (already risk-ranked) until all criticals are covered.
  const set = new Set<string>();
  let criticals = 0;
  for (const u of plan.recommended) {
    if (criticals >= plan.total_exploitable_criticals) break;
    if (u.criticals_removed > 0 || criticals < plan.total_exploitable_criticals) {
      set.add(u.library);
      criticals += u.criticals_removed;
    }
  }
  // Ensure every upgrade that removes a critical is included.
  for (const u of plan.recommended) if (u.criticals_removed > 0) set.add(u.library);
  return set;
}

function UpgradeCard({
  u,
  on,
  toggle,
}: {
  u: Upgrade;
  on: boolean;
  toggle: () => void;
}) {
  return (
    <div className={`card p-4 transition-opacity ${on ? "" : "opacity-55"}`}>
      <div className="flex items-start gap-3">
        <input
          type="checkbox"
          checked={on}
          onChange={toggle}
          className="mt-1 h-4 w-4 accent-low"
          aria-label={`toggle ${u.library} upgrade`}
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="font-display font-semibold text-paper">{u.library}</span>
            <span className="font-mono text-xs text-mist">
              {u.from_versions.join(", ")} <span className="text-low">→ {u.to_version}</span>
            </span>
          </div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-mist">
            <span>{u.app_count} app{u.app_count > 1 ? "s" : ""}</span>
            <span>{u.cves_fixed.length} CVE{u.cves_fixed.length > 1 ? "s" : ""}</span>
            <span className="text-low">−{u.risk_removed.toFixed(0)} risk</span>
            {u.criticals_removed > 0 && (
              <span className="text-crit">{u.criticals_removed} critical fixed</span>
            )}
          </div>
          {u.conflicts.length > 0 && (
            <div className="mt-2 flex items-start gap-1.5 rounded-md border border-high/30 bg-high/5 px-2 py-1.5 text-[11px] text-high">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              <span>
                Introduces a version conflict —{" "}
                {u.conflicts.map((c, i) => (
                  <span key={i} className="font-mono">
                    {c.parent_library} requires {c.constraint}
                    {i < u.conflicts.length - 1 ? "; " : ""}
                  </span>
                ))}
                . Bump {u.conflicts[0].parent_library} too.
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Optimizer() {
  const [plan, setPlan] = useState<FixPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  useEffect(() => {
    fetchFixPlan()
      .then((p) => {
        setPlan(p);
        setSelected(minimalCriticalSet(p));
      })
      .catch((e) => setError(String(e)));
  }, []);

  const stats = useMemo(() => {
    if (!plan) return null;
    const sel = plan.recommended.filter((u) => selected.has(u.library));
    const riskRemoved = sel.reduce((s, u) => s + u.risk_removed, 0);
    const critFixed = sel.reduce((s, u) => s + u.criticals_removed, 0);
    const conflicts = sel.filter((u) => u.conflicts.length > 0).length;
    return {
      count: sel.length,
      riskRemoved,
      residual: Math.max(0, plan.total_exploitable_risk - riskRemoved),
      critFixed,
      critRemaining: plan.total_exploitable_criticals - critFixed,
      pct: plan.total_exploitable_risk ? riskRemoved / plan.total_exploitable_risk : 0,
      conflicts,
    };
  }, [plan, selected]);

  if (error) return <ErrorState message={error} />;
  if (!plan || !stats) return <Loading label="Optimizing remediation…" />;

  function toggle(lib: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(lib) ? next.delete(lib) : next.add(lib);
      return next;
    });
  }

  return (
    <div className="mx-auto max-w-5xl">
      <header className="mb-6">
        <div className="eyebrow flex items-center gap-1.5">
          <Wrench size={13} /> Fix Optimizer
        </div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">
          The cheapest path to safe
        </h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          A report says “you have {plan.total_exploitable_criticals} criticals.” Useless at 2 AM.
          Sentinel finds the minimum set of upgrades that removes the most exploitable risk —
          one shared library often fixes many apps at once.
        </p>
      </header>

      {/* Live what-if summary */}
      <div className="card mb-6 p-5">
        <div className="grid gap-4 sm:grid-cols-4">
          <div>
            <div className="eyebrow">Upgrades selected</div>
            <div className="mt-1 font-display text-3xl font-bold text-paper">{stats.count}</div>
          </div>
          <div>
            <div className="eyebrow">Criticals fixed</div>
            <div className="mt-1 font-display text-3xl font-bold text-low">
              {stats.critFixed}
              <span className="text-lg text-mist">/{plan.total_exploitable_criticals}</span>
            </div>
          </div>
          <div>
            <div className="eyebrow">Exploitable risk removed</div>
            <div className="mt-1 font-display text-3xl font-bold text-low">{Math.round(stats.pct * 100)}%</div>
          </div>
          <div>
            <div className="eyebrow">Conflicts to manage</div>
            <div className="mt-1 font-display text-3xl font-bold" style={{ color: stats.conflicts ? "#F2733B" : "#45B08A" }}>
              {stats.conflicts}
            </div>
          </div>
        </div>
        {/* before -> after risk bar */}
        <div className="mt-4">
          <div className="flex items-center justify-between font-mono text-[11px] text-mist">
            <span>residual exploitable risk</span>
            <span>
              {stats.residual.toFixed(0)} / {plan.total_exploitable_risk.toFixed(0)}
            </span>
          </div>
          <div className="mt-1 h-2.5 w-full overflow-hidden rounded-full bg-panel2">
            <div
              className="h-2.5 rounded-full bg-gradient-to-r from-crit to-high transition-[width] duration-500"
              style={{ width: `${100 - stats.pct * 100}%` }}
            />
          </div>
        </div>
      </div>

      <div className="mb-2 flex items-center gap-2">
        <PackageCheck size={15} className="text-low" />
        <span className="eyebrow">Recommended upgrades — toggle to explore trade-offs</span>
      </div>
      <div className="grid gap-3">
        {plan.recommended.map((u) => (
          <UpgradeCard key={u.library} u={u} on={selected.has(u.library)} toggle={() => toggle(u.library)} />
        ))}
      </div>
    </div>
  );
}
