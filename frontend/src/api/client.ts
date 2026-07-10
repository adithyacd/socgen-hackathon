import type { AnalysisResult } from "./types";

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

export { API_BASE };
