import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Bug, ShieldX, Copy, PackageX } from "lucide-react";
import { fetchThreats } from "../api/client";
import type { Threat } from "../api/types";
import { Loading, ErrorState } from "../components/States";

const TYPE_META: Record<string, { label: string; hex: string; icon: any }> = {
  known_malicious: { label: "Known malicious", hex: "#F0324F", icon: ShieldX },
  typosquat: { label: "Typosquat", hex: "#F2913D", icon: Copy },
  dependency_confusion: { label: "Dependency confusion", hex: "#E7C548", icon: PackageX },
};

function ThreatCard({ t }: { t: Threat }) {
  const meta = TYPE_META[t.threat_type] ?? { label: t.threat_type, hex: "#8A97B1", icon: Bug };
  const Icon = meta.icon;
  return (
    <div className="card p-4" style={{ borderColor: `${meta.hex}44` }}>
      <div className="flex items-start gap-3">
        <div className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg" style={{ background: `${meta.hex}1a`, color: meta.hex }}>
          <Icon size={16} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="font-mono font-semibold text-paper">{t.library}</span>
            <span className="font-mono text-[11px] text-mist">v{t.version}</span>
            <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: `${meta.hex}1a`, color: meta.hex }}>{meta.label}</span>
            <span className="ml-auto font-mono text-[11px] text-mist">{Math.round(t.confidence * 100)}% conf</span>
          </div>
          <p className="mt-1 text-sm text-mist">{t.detail}</p>
          <div className="mt-1.5 flex items-center gap-3 text-[11px] text-mist">
            {t.suggested && <span>impersonates <span className="font-mono text-paper">{t.suggested}</span></span>}
            <Link to={`/app/${t.app_id}`} className="hover:text-signal">{t.app}</Link>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Threats() {
  const [threats, setThreats] = useState<Threat[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchThreats().then((r) => setThreats(r.threats)).catch((e) => setError(String(e)));
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!threats) return <Loading label="Hunting supply-chain threats…" />;

  const counts = threats.reduce((acc, t) => ((acc[t.threat_type] = (acc[t.threat_type] ?? 0) + 1), acc), {} as Record<string, number>);

  return (
    <div className="mx-auto max-w-4xl">
      <header className="mb-6">
        <div className="eyebrow flex items-center gap-1.5"><Bug size={13} /> Supply-chain threats</div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">The risks a CVE list can’t see</h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          Known CVEs are the <em>known</em> risk. Real supply-chain attacks — SolarWinds, event-stream,
          ua-parser-js, xz-utils — are impostor or compromised packages. Sentinel hunts typosquats,
          dependency confusion, and known-malicious packages that CVE scanners miss entirely.
        </p>
      </header>

      <div className="mb-5 grid grid-cols-3 gap-3">
        {Object.entries(TYPE_META).map(([k, meta]) => (
          <div key={k} className="card p-3 text-center">
            <div className="font-display text-2xl font-bold" style={{ color: meta.hex }}>{counts[k] ?? 0}</div>
            <div className="text-[11px] text-mist">{meta.label}</div>
          </div>
        ))}
      </div>

      {threats.length === 0 ? (
        <div className="card p-8 text-center text-sm text-mist">
          No supply-chain threats detected in this dataset. Try the <Link to="/scan" className="text-signal">Scan</Link> view
          with a real manifest that contains a typosquat or a compromised package.
        </div>
      ) : (
        <div className="grid gap-3">
          {threats.map((t, i) => <ThreatCard key={i} t={t} />)}
        </div>
      )}
    </div>
  );
}
