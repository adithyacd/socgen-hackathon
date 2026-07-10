import { NavLink } from "react-router-dom";
import {
  LayoutGrid,
  Siren,
  Wrench,
  Sparkles,
  Target,
  Radar,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";

const NAV: { to: string; label: string; icon: LucideIcon }[] = [
  { to: "/", label: "Portfolio", icon: LayoutGrid },
  { to: "/warroom", label: "War Room", icon: Siren },
  { to: "/optimizer", label: "Fix Optimizer", icon: Wrench },
  { to: "/copilot", label: "Copilot", icon: Sparkles },
  { to: "/accuracy", label: "Accuracy", icon: Target },
];

function Brand() {
  return (
    <div className="flex items-center gap-3 px-3 py-1">
      <div className="grid h-9 w-9 place-items-center rounded-lg border border-signal/40 bg-signal/10 text-signal shadow-glow">
        <Radar size={18} strokeWidth={2.2} />
      </div>
      <div className="leading-tight">
        <div className="font-display text-lg font-bold tracking-tight text-paper">Sentinel</div>
        <div className="eyebrow !tracking-[0.14em]">Supply Chain Risk</div>
      </div>
    </div>
  );
}

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col gap-6 border-r border-line bg-panel/60 px-4 py-6 md:flex">
        <Brand />
        <nav className="flex flex-col gap-1">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) => `navlink ${isActive ? "navlink-active" : ""}`}
            >
              <Icon size={18} strokeWidth={2} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto px-3">
          <div className="rounded-lg border border-line bg-panel2/60 p-3 text-xs text-mist">
            <div className="font-mono text-[11px] uppercase tracking-widest text-signal">Demo</div>
            <p className="mt-1 leading-relaxed">
              10 apps · synthetic SBOMs · a planted Log4Shell scenario across the portfolio.
            </p>
          </div>
        </div>
      </aside>

      {/* Mobile top bar */}
      <header className="fixed inset-x-0 top-0 z-20 flex items-center gap-2 border-b border-line bg-ink/90 px-3 py-2 backdrop-blur md:hidden">
        <Brand />
        <nav className="ml-auto flex gap-1 overflow-x-auto">
          {NAV.map(({ to, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `grid h-9 w-9 place-items-center rounded-lg ${
                  isActive ? "bg-panel2 text-paper" : "text-mist"
                }`
              }
            >
              <Icon size={18} />
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="min-w-0 flex-1 px-5 pb-16 pt-16 md:px-8 md:pt-8">{children}</main>
    </div>
  );
}
