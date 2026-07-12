// Client-side Copilot: turns a question into a structured query executed over the
// already-loaded analysis, so it works with no server (mirrors the backend logic).
import type { AnalysisResult, CopilotAnswer } from "../api/types";

export const SUGGESTIONS = [
  "Which internet-facing apps have exploitable criticals?",
  "Show all GPL license conflicts",
  "Which apps are exposed to Log4Shell?",
  "List unmaintained libraries",
  "Which transitive dependencies are exploitable?",
];

interface Spec {
  entity: "apps" | "findings";
  risk_type?: string;
  severity?: string;
  reachable?: boolean;
  license_family?: string;
  internet_facing?: boolean;
  business_criticality?: string;
  library?: string;
  cve?: string;
  transitive?: boolean;
}

const VULN = new Set(["vulnerable", "transitive_vuln"]);

function parse(q: string): Spec {
  const ql = q.toLowerCase();
  const s: Spec = { entity: "findings" };
  if (ql.includes("app") && !ql.includes("librar") && !ql.includes("dependenc")) s.entity = "apps";
  if (ql.includes("gpl") || ql.includes("agpl") || ql.includes("copyleft") || ql.includes("licen")) {
    s.risk_type = "license_conflict";
    if (ql.includes("gpl")) s.license_family = "GPL";
  }
  if (ql.includes("unmaintain") || ql.includes("abandon") || ql.includes("stale") || ql.includes("outdated")) s.risk_type = "unmaintained";
  if (ql.includes("exploitab") || ql.includes("reachab")) s.reachable = true;
  if (ql.includes("unreachab") || ql.includes("suppress") || ql.includes("not exploitab")) s.reachable = false;
  if (ql.includes("critical")) s.severity = "critical";
  else if (ql.includes(" high")) s.severity = "high";
  if (ql.includes("internet") || ql.includes("external") || ql.includes("public")) s.internet_facing = true;
  if (ql.includes("transitive") || ql.includes("nested") || ql.includes("indirect")) {
    s.transitive = true;
    if (!s.risk_type) s.risk_type = "transitive_vuln";
  }
  if (ql.includes("log4j") || ql.includes("log4shell")) s.library = "log4j";
  if (ql.includes("vulnerab") && !s.risk_type) s.risk_type = "vulnerable";
  const cve = q.replace(/,/g, " ").split(/\s+/).find((t) => t.toUpperCase().startsWith("CVE-"));
  if (cve) s.cve = cve.toUpperCase();
  return s;
}

function execute(data: AnalysisResult, s: Spec) {
  const apps = new Map(data.apps.map((a) => [a.app_id, a]));
  const rows: any[] = [];
  for (const f of data.findings) {
    const app = apps.get(f.app_id);
    if (!app) continue;
    if (s.risk_type) {
      const types = new Set([f.risk_type, ...(f.secondary_risks ?? [])]);
      if (!types.has(s.risk_type)) continue;
    }
    if (s.severity && f.severity !== s.severity) continue;
    if (s.reachable !== undefined) {
      const isReach = f.is_reachable !== false;
      if (isReach !== s.reachable) continue;
    }
    if (s.transitive !== undefined && f.is_direct === s.transitive) continue;
    if (s.library && !f.library.toLowerCase().includes(s.library.toLowerCase())) continue;
    if (s.cve && !f.cve_ids.includes(s.cve)) continue;
    if (s.license_family && !(f.detail ?? "").toLowerCase().includes(s.license_family.toLowerCase())) continue;
    if (s.internet_facing !== undefined && app.internet_facing !== s.internet_facing) continue;
    if (s.business_criticality && app.business_criticality !== s.business_criticality) continue;
    rows.push({
      app_id: f.app_id, app: app.name, library: f.library, version: f.version,
      risk_type: f.risk_type, severity: f.severity,
      reachable: VULN.has(f.risk_type) ? f.is_reachable !== false : null, cves: f.cve_ids,
    });
  }
  if (s.entity === "apps") {
    const seen = new Set<string>();
    const out: any[] = [];
    for (const r of rows) if (!seen.has(r.app_id)) { seen.add(r.app_id); out.push({ app_id: r.app_id, app: r.app }); }
    return out;
  }
  return rows;
}

function describe(s: Spec): string {
  const bits: string[] = [];
  if (s.severity) bits.push(s.severity);
  if (s.reachable === true) bits.push("exploitable");
  if (s.reachable === false) bits.push("unreachable");
  if (s.transitive) bits.push("transitive");
  if (s.risk_type === "license_conflict") bits.push(`${s.license_family ?? ""} license-conflicting`.trim());
  else if (s.risk_type === "unmaintained") bits.push("unmaintained");
  else if (s.risk_type === "vulnerable" || s.risk_type === "transitive_vuln") bits.push("vulnerable");
  if (s.library) bits.push(s.library);
  let noun = s.entity === "apps" ? "applications" : "dependencies";
  if (s.internet_facing) noun = "internet-facing " + noun;
  return `${bits.join(" ")} ${noun}`.trim();
}

export function answerLocal(data: AnalysisResult, question: string): CopilotAnswer {
  const spec = parse(question);
  const results = execute(data, spec);
  const n = results.length;
  const desc = describe(spec);
  let text: string;
  if (n === 0) text = `No ${desc} found in the current portfolio.`;
  else if (spec.entity === "apps") {
    text = `${n} ${desc}: ${results.slice(0, 8).map((r: any) => r.app).join(", ")}${n > 8 ? "…" : ""}.`;
  } else {
    text = `${n} ${desc}: ${results.slice(0, 6).map((r: any) => `${r.library} in ${r.app}`).join(", ")}${n > 6 ? "…" : ""}.`;
  }
  const query: Record<string, any> = {};
  Object.entries(spec).forEach(([k, v]) => { if (v !== undefined) query[k] = v; });
  return { question, answer: text, query, matches: results.slice(0, 50), match_count: n, source: "rules" };
}
