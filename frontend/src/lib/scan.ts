// Client-side SBOM scan: parses a real manifest and runs the supply-chain threat +
// license checks in the browser, so upload works with no server (mirrors the backend).
import type { ScanResult, Threat, Finding, Severity } from "../api/types";

const POPULAR = new Set([
  "lodash", "react", "react-dom", "express", "axios", "chalk", "commander", "moment",
  "request", "debug", "async", "webpack", "babel-core", "jest", "typescript", "vue",
  "underscore", "colors", "node-fetch", "minimist", "yargs", "uuid", "dotenv", "redux",
  "requests", "urllib3", "numpy", "pandas", "flask", "django", "setuptools", "pip",
  "cryptography", "pyyaml", "jinja2", "click", "boto3", "scipy", "pillow", "certifi",
  "sqlalchemy", "werkzeug", "beautifulsoup4", "pytest", "six", "wheel", "jackson-databind",
  "guava", "log4j-core", "slf4j-api", "commons-lang3", "gson", "spring-core", "netty-all",
  "commons-io", "junit", "hibernate-core", "commons-codec", "gin", "gorilla-mux", "logrus",
  "cobra", "testify", "grpc", "protobuf",
]);
const MALICIOUS: Record<string, string | null> = {
  "event-stream": "3.3.6", "ua-parser-js": "0.7.29", "node-ipc": "10.1.1", coa: "2.0.3",
  rc: "1.3.9", colors: "1.4.44-liberty-2", faker: "6.6.6", "flatmap-stream": null,
  "eslint-scope": "3.7.2", "left-pad": null, xz: "5.6.0", liblzma: "5.6.0", ctx: null,
};
const VIRAL = new Set(["GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"]);

function damerau(a: string, b: string, cap = 1): number {
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > cap) return cap + 1;
  const d = Array.from({ length: la + 1 }, () => new Array(lb + 1).fill(0));
  for (let i = 0; i <= la; i++) d[i][0] = i;
  for (let j = 0; j <= lb; j++) d[0][j] = j;
  for (let i = 1; i <= la; i++)
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  return d[la][lb];
}
const closestPopular = (name: string) => {
  for (const p of POPULAR) if (p !== name && damerau(name, p, 1) === 1) return p;
  return null;
};
const major = (v: string) => { const n = parseInt(v.split(".")[0], 10); return isNaN(n) ? 0 : n; };
const cleanVer = (v: string) => (v || "").replace(/^[\^~>=<!\s]+/, "").split(/[, ]/)[0] || "0.0.0";

interface Dep { library: string; version: string; license: string }

function detect(content: string): string {
  const s = content.trimStart();
  if (s.startsWith("{")) {
    try {
      const d = JSON.parse(content);
      if (d.bomFormat || d.components) return "cyclonedx";
      if (d.spdxVersion || d.packages) return "spdx";
      if (d.dependencies || d.devDependencies || d.name) return "package.json";
    } catch { /* fall through */ }
  }
  return "requirements.txt";
}

function parseManifest(content: string, fmt: string): Dep[] {
  const f = fmt === "auto" ? detect(content) : fmt;
  const out: Dep[] = [];
  if (f === "package.json") {
    const d = JSON.parse(content);
    for (const sec of ["dependencies", "devDependencies", "optionalDependencies"])
      for (const [name, ver] of Object.entries(d[sec] ?? {})) out.push({ library: name, version: cleanVer(String(ver)), license: "UNKNOWN" });
  } else if (f === "requirements.txt") {
    for (const line of content.split("\n")) {
      const l = line.split("#")[0].trim();
      if (!l || l.startsWith("-")) continue;
      const m = l.match(/^([A-Za-z0-9._-]+)\s*(?:[=<>!~]+\s*([0-9][^;,\s]*))?/);
      if (m) out.push({ library: m[1], version: m[2] || "0.0.0", license: "UNKNOWN" });
    }
  } else if (f === "cyclonedx") {
    const d = JSON.parse(content);
    for (const c of d.components ?? []) {
      const lic = (c.licenses ?? [])[0]?.license;
      out.push({ library: c.name ?? "", version: c.version ?? "0.0.0", license: lic?.id ?? lic?.name ?? "UNKNOWN" });
    }
  } else if (f === "spdx") {
    const d = JSON.parse(content);
    for (const p of d.packages ?? [])
      out.push({ library: p.name ?? "", version: p.versionInfo ?? "0.0.0", license: p.licenseConcluded ?? p.licenseDeclared ?? "UNKNOWN" });
  }
  return out.filter((d) => d.library);
}

function scanThreats(deps: Dep[]): Threat[] {
  const out: Threat[] = [];
  const seen = new Set<string>();
  const t = (d: Dep, type: any, sev: Severity, conf: number, detail: string, suggested: string): Threat =>
    ({ app_id: "UPLOAD", app: "Uploaded project", library: d.library, version: d.version, threat_type: type, severity: sev, confidence: Math.round(conf * 100) / 100, detail, suggested });
  for (const d of deps) {
    const name = d.library.toLowerCase();
    const key = `${name}@${d.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (name in MALICIOUS) {
      const bad = MALICIOUS[name];
      if (bad === null || bad === d.version) { out.push(t(d, "known_malicious", "critical", 0.95, `'${d.library}' matches a known compromised/protestware package${bad ? ` (bad version ${bad})` : ""}.`, "")); continue; }
    }
    if (POPULAR.has(name) && major(d.version) >= 50) { out.push(t(d, "dependency_confusion", "high", 0.7, `'${d.library}' is a well-known public package pinned to an implausible version ${d.version} — a classic dependency-confusion signal.`, d.library)); continue; }
    if (!POPULAR.has(name) && name.length >= 4) {
      const pop = closestPopular(name);
      if (pop) out.push(t(d, "typosquat", "high", 0.85, `'${d.library}' is one edit from the popular package '${pop}' — likely typosquat.`, pop));
    }
  }
  return out.sort((a, b) => b.confidence - a.confidence);
}

function licenseFindings(deps: Dep[]): Finding[] {
  const mk = (d: Dep, risk: any, sev: Severity, detail: string): Finding => ({
    app_id: "UPLOAD", library: d.library, version: d.version, is_direct: true, risk_type: risk,
    severity: sev, secondary_risks: [], cve_ids: [], exploitability: "", is_reachable: null,
    detail, score: 0, paths: [], fixed_versions: {}, max_cvss: 0, kev: false, epss: 0,
  });
  const out: Finding[] = [];
  for (const d of deps) {
    if (VIRAL.has(d.license)) out.push(mk(d, "license_conflict", "critical", `Copyleft license '${d.license}' is incompatible with a proprietary application.`));
    else if (d.license === "UNKNOWN") out.push(mk(d, "license_unknown", "high", `License '${d.license}' is unrecognized — legal review needed.`));
  }
  return out;
}

export function scanLocal(content: string, fmt = "auto"): ScanResult {
  const resolved = fmt === "auto" ? detect(content) : fmt;
  let parsed: Dep[];
  try {
    parsed = parseManifest(content, fmt);
  } catch {
    return { format: resolved, dependency_count: 0, app: null, findings: [], threats: [], summary: { vulnerable: 0, license: 0, unmaintained: 0, threats: 0 }, error: "Couldn't parse the input." };
  }
  if (!parsed.length)
    return { format: resolved, dependency_count: 0, app: null, findings: [], threats: [], summary: { vulnerable: 0, license: 0, unmaintained: 0, threats: 0 }, error: "No dependencies parsed from the input." };
  const threats = scanThreats(parsed);
  const findings = licenseFindings(parsed);
  return {
    format: resolved, dependency_count: parsed.length, app: null, findings, threats,
    summary: { vulnerable: 0, license: findings.length, unmaintained: 0, threats: threats.length },
  };
}
