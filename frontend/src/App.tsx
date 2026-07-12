import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { AnalysisProvider } from "./lib/analysisContext";
import Portfolio from "./views/Portfolio";
import AppDetail from "./views/AppDetail";
import Accuracy from "./views/Accuracy";
import WarRoom from "./views/WarRoom";
import Optimizer from "./views/Optimizer";
import Copilot from "./views/Copilot";
import Threats from "./views/Threats";
import Audit from "./views/Audit";
import Scan from "./views/Scan";

// Landing is heavy (three.js) — load it only when someone visits "/".
const Landing = lazy(() => import("./views/Landing"));

const shell = (node: ReactNode) => <Layout>{node}</Layout>;

export default function App() {
  return (
    <AnalysisProvider>
      <Routes>
        <Route path="/" element={<Suspense fallback={null}><Landing /></Suspense>} />
        <Route path="/portfolio" element={shell(<Portfolio />)} />
        <Route path="/app/:appId" element={shell(<AppDetail />)} />
        <Route path="/warroom" element={shell(<WarRoom />)} />
        <Route path="/optimizer" element={shell(<Optimizer />)} />
        <Route path="/threats" element={shell(<Threats />)} />
        <Route path="/scan" element={shell(<Scan />)} />
        <Route path="/copilot" element={shell(<Copilot />)} />
        <Route path="/audit" element={shell(<Audit />)} />
        <Route path="/accuracy" element={shell(<Accuracy />)} />
        <Route path="*" element={<Navigate to="/portfolio" replace />} />
      </Routes>
    </AnalysisProvider>
  );
}
