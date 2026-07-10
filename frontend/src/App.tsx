import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Placeholder from "./components/Placeholder";
import { AnalysisProvider } from "./lib/analysisContext";
import Portfolio from "./views/Portfolio";

export default function App() {
  return (
    <AnalysisProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Portfolio />} />
          <Route path="/app/:appId" element={<Placeholder title="App Detail" />} />
          <Route path="/warroom" element={<Placeholder title="Zero-Day War Room" />} />
          <Route path="/optimizer" element={<Placeholder title="Fix Optimizer" />} />
          <Route path="/copilot" element={<Placeholder title="Copilot" />} />
          <Route path="/accuracy" element={<Placeholder title="Accuracy" />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </AnalysisProvider>
  );
}
