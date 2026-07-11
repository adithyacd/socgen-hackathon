// Mirrors backend/app/schemas.py + models.py

export type Severity = "critical" | "high" | "medium" | "low";
export type RiskType =
  | "vulnerable"
  | "transitive_vuln"
  | "license_conflict"
  | "unmaintained"
  | "clean";

export interface Finding {
  app_id: string;
  library: string;
  version: string;
  is_direct: boolean;
  risk_type: RiskType;
  severity: Severity;
  secondary_risks: string[];
  cve_ids: string[];
  is_reachable: boolean | null;
  detail: string;
  score: number;
  paths: string[][];
  fixed_versions: Record<string, string | null>;
  max_cvss: number;
  kev: boolean;
  epss: number;
}

export interface AppRisk {
  app_id: string;
  name: string;
  business_criticality: Severity;
  owner: string;
  internet_facing: boolean;
  environment: string;
  ecosystem: string;
  license_context: string;
  risk_score: number;
  risk_band: Severity;
  dependency_count: number;
  direct_count: number;
  counts: Record<string, number>;
  top_findings: Finding[];
}

export interface Summary {
  app_count: number;
  dependency_count: number;
  finding_count: number;
  exploitable_criticals: number;
  counts: Record<string, number>;
  highest_risk_app: string;
}

export interface AnalysisResult {
  generated_at: string;
  apps: AppRisk[];
  findings: Finding[];
  summary: Summary;
  metrics: Record<string, any>;
}

export interface GraphNode {
  id: string;
  library: string;
  version: string;
  kind: "app" | "library";
  is_direct: boolean;
  is_vulnerable: boolean;
  is_reachable: boolean | null;
  severity: Severity | null;
  risk_types: string[];
  cve_ids: string[];
  license: string;
  last_updated: string;
  maintainer_count: number;
  score: number;
  depth: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  used: boolean;
  is_direct: boolean;
}

export interface AppGraph {
  app: AppRisk;
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: Finding[];
}

export interface WarRoomCve {
  cve_id: string;
  description: string;
  cvss: number;
  severity: Severity;
  kev: boolean;
  epss: number;
  affected_library: string;
  fixed_version: string | null;
  affected_apps: number;
  exploitable_apps: number;
}

export interface AppImpact {
  app_id: string;
  name: string;
  business_criticality: Severity;
  internet_facing: boolean;
  environment: string;
  library: string;
  version: string;
  is_direct: boolean;
  is_reachable: boolean;
  path: string[];
}

export interface WarRoomImpact {
  cve: WarRoomCve;
  affected: AppImpact[];
  affected_count: number;
  exploitable_count: number;
  blast_radius: string;
  narrative: string;
}

export interface UpgradeConflict {
  app_id: string;
  parent_library: string;
  constraint: string;
}

export interface Upgrade {
  library: string;
  to_version: string;
  from_versions: string[];
  cves_fixed: string[];
  apps_affected: string[];
  app_count: number;
  risk_removed: number;
  criticals_removed: number;
  conflicts: UpgradeConflict[];
}

export interface FixPlan {
  total_exploitable_risk: number;
  total_exploitable_criticals: number;
  total_exploitable_findings: number;
  recommended: Upgrade[];
}

export interface CopilotMatch {
  app_id: string;
  app: string;
  library?: string;
  version?: string;
  risk_type?: string;
  severity?: Severity;
  reachable?: boolean | null;
  cves?: string[];
}

export interface CopilotAnswer {
  question: string;
  answer: string;
  query: Record<string, any>;
  matches: CopilotMatch[];
  match_count: number;
  source: "llm" | "rules";
}
