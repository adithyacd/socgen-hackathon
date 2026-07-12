import { useEffect, useState } from "react";
import { ShieldQuestion, AlertTriangle, Info } from "lucide-react";
import { fetchAudit } from "../api/client";
import type { AuditIssue, AuditReport } from "../api/types";
import { Loading, ErrorState } from "../components/States";

const SEV_HEX: Record<string, string> = { high: "#E60028", medium: "#F2733B", low: "#D9A441", info: "#8A8A93" };

function IssueCard({ issue }: { issue: AuditIssue }) {
  const hex = SEV_HEX[issue.severity] ?? "#8A8A93";
  const Icon = issue.severity === "info" ? Info : AlertTriangle;
  return (
    <div className="card p-4">
      <div className="flex items-start gap-3">
        <Icon size={16} className="mt-0.5 shrink-0" style={{ color: hex }} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="font-display font-semibold text-paper">{issue.issue}</span>
            <span className="rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold" style={{ background: `${hex}1a`, color: hex }}>{issue.metric}</span>
          </div>
          <p className="mt-1 text-sm text-mist">{issue.detail}</p>
          {issue.evidence.length > 0 && (
            <ul className="mt-2 space-y-1 rounded-lg border border-line bg-panel2/50 p-2.5">
              {issue.evidence.map((e, i) => (
                <li key={i} className="font-mono text-[11px] text-paper">• {e}</li>
              ))}
            </ul>
          )}
          {issue.recommendation && (
            <p className="mt-2 text-[12px] text-low">→ {issue.recommendation}</p>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Audit() {
  const [report, setReport] = useState<AuditReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAudit().then(setReport).catch((e) => setError(String(e)));
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!report) return <Loading label="Auditing the benchmark…" />;

  const noisy = report.issue_count > 0;
  return (
    <div className="mx-auto max-w-4xl">
      <header className="mb-6">
        <div className="eyebrow flex items-center gap-1.5"><ShieldQuestion size={13} /> Benchmark integrity auditor</div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">We audited the ground truth</h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          Every other team optimizes to <em>match</em> the provided labels. We interrogated them —
          where they contradict the CVE database, contradict each other, or disagree with CVSS.
          A detector should be robust to a noisy benchmark, not overfit to it.
        </p>
      </header>

      <div className="card mb-6 flex items-center gap-6 p-5">
        <div className="text-center">
          <div className="eyebrow">Integrity</div>
          <div className="font-display text-4xl font-bold" style={{ color: noisy ? "#F2733B" : "#45B08A" }}>
            {report.integrity_score}<span className="text-lg text-mist">/100</span>
          </div>
        </div>
        <div className="h-12 w-px bg-line" />
        <div>
          <div className="font-display text-lg font-semibold" style={{ color: noisy ? "#F2733B" : "#45B08A" }}>{report.verdict}</div>
          <div className="mt-0.5 text-sm text-mist">
            {report.summary.version_inconsistent_vuln_labels} version-inconsistent labels ·
            {" "}{report.summary.contradictions} contradictory library@version pairs ·
            {" "}{report.total_labels} labels audited
          </div>
        </div>
      </div>

      <div className="grid gap-3">
        {report.issues.map((issue, i) => <IssueCard key={i} issue={issue} />)}
      </div>

      <p className="mt-4 text-xs text-mist">
        Sentinel reports honestly against these labels and uses a robust below-fixed-version rule —
        so our numbers reflect the tool, not overfitting to noise.
      </p>
    </div>
  );
}
