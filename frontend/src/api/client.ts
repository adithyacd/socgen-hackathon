import type {
  AnalysisResult,
  AppGraph,
  CopilotAnswer,
  FixPlan,
  WarRoomCve,
  WarRoomImpact,
} from "./types";

// In dev, hit the FastAPI server. For the static deploy build, set
// VITE_API_BASE="" and drop a prebuilt analysis.json next to index.html.
const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

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
      answer: "Free-form questions need the live backend. Try one of the suggested questions.",
      query: {},
      matches: [],
      match_count: 0,
      source: "rules",
    }
  );
}

export { API_BASE };
