import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Placeholder from "./components/Placeholder";
import { AnalysisProvider } from "./lib/analysisContext";
import Portfolio from "./views/Portfolio";
import AppDetail from "./views/AppDetail";
import Accuracy from "./views/Accuracy";
import WarRoom from "./views/WarRoom";

export default function App() {
  return (
    <AnalysisProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Portfolio />} />
          <Route path="/app/:appId" element={<AppDetail />} />
          <Route path="/warroom" element={<WarRoom />} />
          <Route path="/optimizer" element={<Placeholder title="Fix Optimizer" />} />
          <Route path="/copilot" element={<Placeholder title="Copilot" />} />
          <Route path="/accuracy" element={<Accuracy />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </AnalysisProvider>
  );
}
