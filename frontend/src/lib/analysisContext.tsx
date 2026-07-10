import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { fetchAnalysis } from "../api/client";
import type { AnalysisResult } from "../api/types";

interface State {
  data: AnalysisResult | null;
  loading: boolean;
  error: string | null;
}

const Ctx = createContext<State>({ data: null, loading: true, error: null });

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ data: null, loading: true, error: null });

  useEffect(() => {
    let alive = true;
    fetchAnalysis()
      .then((d) => alive && setState({ data: d, loading: false, error: null }))
      .catch((e) => alive && setState({ data: null, loading: false, error: String(e) }));
    return () => {
      alive = false;
    };
  }, []);

  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}

export const useAnalysis = () => useContext(Ctx);
