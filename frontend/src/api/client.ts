import type {
  AnalysisResult,
  AppGraph,
  AuditReport,
  CopilotAnswer,
  FixPlan,
  ScanResult,
  Threat,
  WarRoomCve,
  WarRoomImpact,
} from "./types";

// If VITE_API_BASE is explicitly set (a live backend URL), use it. Otherwise the dev
// server talks to the local FastAPI, and any production build runs fully static
// (relative JSON next to index.html) — so a frontend-only deploy never calls a backend.
const API_BASE =
  import.meta.env.VITE_API_BASE || (import.meta.env.DEV ? "http://localhost:8000" : "");

async function getJSON<T>(path: string): Promise<T> {
  const url = API_BASE ? `${API_BASE}${path}` : `.${path}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  return (await res.json()) as T;
}

export async function fetchAnalysis(): Promise<AnalysisResult> {
  // API_BASE="" (static mode) reads ./analysis.json; otherwise /api/analysis.
  return getJSON<AnalysisResult>(API_BASE ? "/api/analysis" : "/analysis.json");
}

export async function fetchAppGraph(appId: string): Promise<AppGraph> {
  // Static mode reads a prebuilt per-app graph file.
  return getJSON<AppGraph>(
    API_BASE ? `/api/apps/${appId}/graph` : `/graphs/${appId}.json`,
  );
}

export async function fetchWarRoomCves(): Promise<WarRoomCve[]> {
  return getJSON<WarRoomCve[]>(API_BASE ? "/api/warroom/cves" : "/warroom/cves.json");
}

export async function fetchWarRoomImpact(cve: string): Promise<WarRoomImpact> {
  return getJSON<WarRoomImpact>(API_BASE ? `/api/warroom/impact/${cve}` : `/warroom/${cve}.json`);
}

export async function fetchFixPlan(): Promise<FixPlan> {
  return getJSON<FixPlan>(API_BASE ? "/api/optimizer/plan" : "/optimizer.json");
}

export async function fetchCopilotSuggestions(): Promise<{ suggestions: string[]; llm_enabled: boolean }> {
  if (API_BASE) return getJSON("/api/copilot/suggestions");
  const canned = await getJSON<Record<string, CopilotAnswer>>("/copilot.json").catch(
    () => ({}) as Record<string, CopilotAnswer>,
  );
  return { suggestions: Object.keys(canned), llm_enabled: false };
}

export async function askCopilot(question: string): Promise<CopilotAnswer> {
  if (API_BASE) {
    const res = await fetch(`${API_BASE}/api/copilot/ask`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  }
  // Static mode: only the precomputed suggested questions are answerable.
  const canned = await getJSON<Record<string, CopilotAnswer>>("/copilot.json").catch(
    () => ({}) as Record<string, CopilotAnswer>,
  );
  return (
    canned[question] ?? {
      question,
      answer: "Try one of the suggested questions.",
      query: {},
      matches: [],
      match_count: 0,
      source: "rules",
    }
  );
}

export async function fetchThreats(): Promise<{ threats: Threat[]; count: number }> {
  return getJSON(API_BASE ? "/api/threats" : "/threats.json");
}

export async function fetchAudit(): Promise<AuditReport> {
  return getJSON(API_BASE ? "/api/audit" : "/audit.json");
}

export async function scanManifest(content: string, format = "auto"): Promise<ScanResult> {
  if (API_BASE) {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, format }),
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  }
  // Static mode: return the precomputed sample scan.
  return getJSON<ScanResult>("/scan-sample.json");
}

export { API_BASE };
