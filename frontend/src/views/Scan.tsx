import { useState } from "react";
import { Link } from "react-router-dom";
import { FileUp, Play, ShieldX, Copy, PackageX, ScrollText } from "lucide-react";
import { scanManifest, API_BASE } from "../api/client";
import type { ScanResult, Threat } from "../api/types";
import { scanLocal } from "../lib/scan";
import { severityText, RISK_TYPE_LABEL } from "../lib/risk";

const SAMPLE = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "components": [
    { "type": "library", "name": "lodash", "version": "4.17.21", "licenses": [{ "license": { "id": "MIT" } }] },
    { "type": "library", "name": "requsts", "version": "2.28.0", "licenses": [{ "license": { "id": "MIT" } }] },
    { "type": "library", "name": "lodahs", "version": "1.0.0", "licenses": [{ "license": { "id": "MIT" } }] },
    { "type": "library", "name": "event-stream", "version": "3.3.6", "licenses": [{ "license": { "id": "MIT" } }] },
    { "type": "library", "name": "express", "version": "99.0.0", "licenses": [{ "license": { "id": "MIT" } }] },
    { "type": "library", "name": "internal-auth-sdk", "version": "5.2.0", "licenses": [{ "license": { "id": "GPL-3.0" } }] }
  ]
}`;

const T_ICON: Record<string, any> = { known_malicious: ShieldX, typosquat: Copy, dependency_confusion: PackageX };
const T_HEX: Record<string, string> = { known_malicious: "#E60028", typosquat: "#F2733B", dependency_confusion: "#D9A441" };

function ThreatRow({ t }: { t: Threat }) {
  const Icon = T_ICON[t.threat_type] ?? ShieldX;
  const hex = T_HEX[t.threat_type] ?? "#E60028";
  return (
    <div className="flex items-start gap-2 rounded-lg border p-2.5" style={{ borderColor: `${hex}44` }}>
      <Icon size={15} className="mt-0.5 shrink-0" style={{ color: hex }} />
      <div>
        <div className="font-mono text-sm text-paper">{t.library} <span className="text-mist">v{t.version}</span></div>
        <div className="text-xs text-mist">{t.detail}</div>
      </div>
    </div>
  );
}

export default function Scan() {
  const [content, setContent] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    if (!content.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = API_BASE ? await scanManifest(content, "auto") : scanLocal(content, "auto");
      if (r.error) setError(r.error);
      setResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-4xl">
      <header className="mb-6">
        <div className="eyebrow flex items-center gap-1.5"><FileUp size={13} /> Scan a real SBOM</div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">It works on real projects</h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          Paste a real <span className="font-mono text-paper">package.json</span>,
          {" "}<span className="font-mono text-paper">requirements.txt</span>, or a CycloneDX / SPDX SBOM.
          Sentinel parses it and runs the license and supply-chain threat engines on it live.
        </p>
      </header>

      <div className="card p-4">
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Paste package.json / requirements.txt / CycloneDX / SPDX…"
          className="h-44 w-full resize-y rounded-lg border border-line bg-panel2 p-3 font-mono text-xs text-paper placeholder:text-mist/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-signal"
        />
        <div className="mt-3 flex items-center gap-3">
          <button onClick={run} disabled={busy || !content.trim()} className="inline-flex items-center gap-2 rounded-lg bg-signal px-4 py-2 font-display font-semibold text-white transition-transform hover:scale-[1.02] disabled:opacity-40">
            <Play size={16} /> {busy ? "Scanning…" : "Scan"}
          </button>
          <button onClick={() => setContent(SAMPLE)} className="inline-flex items-center gap-1.5 text-xs text-mist hover:text-paper">
            <ScrollText size={14} /> Load a sample with hidden threats
          </button>
        </div>
      </div>

      {error && <div className="mt-4 rounded-lg border border-crit/30 bg-crit/5 p-3 text-sm text-crit">{error}</div>}

      {result && !result.error && (
        <div className="mt-5 space-y-4">
          <div className="grid grid-cols-4 gap-3">
            {[
              ["Dependencies", result.dependency_count, "#F4F4F5"],
              ["Vulnerable", result.summary.vulnerable, "#E60028"],
              ["License issues", result.summary.license, "#79808F"],
              ["Threats", result.summary.threats, "#F2733B"],
            ].map(([l, v, c]) => (
              <div key={l as string} className="card p-3 text-center">
                <div className="font-display text-2xl font-bold" style={{ color: c as string }}>{v as number}</div>
                <div className="text-[11px] text-mist">{l as string}</div>
              </div>
            ))}
          </div>
          <div className="font-mono text-[11px] text-mist">parsed as {result.format}</div>

          {result.threats.length > 0 && (
            <div>
              <div className="eyebrow mb-2 text-crit">Supply-chain threats — what a CVE scanner misses</div>
              <div className="grid gap-2 sm:grid-cols-2">
                {result.threats.map((t, i) => <ThreatRow key={i} t={t} />)}
              </div>
            </div>
          )}

          {result.findings.length > 0 && (
            <div>
              <div className="eyebrow mb-2">Findings</div>
              <div className="card divide-y divide-line">
                {result.findings.slice(0, 20).map((f, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2">
                    <span className="font-mono text-xs text-paper">{f.library} <span className="text-mist">v{f.version}</span></span>
                    <span className="text-[11px] text-mist">{RISK_TYPE_LABEL[f.risk_type as keyof typeof RISK_TYPE_LABEL] ?? f.risk_type}</span>
                    <span className={`font-mono text-[10px] font-semibold ${severityText[f.severity]}`}>{f.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
