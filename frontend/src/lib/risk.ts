import type { RiskType, Severity } from "../api/types";

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#F0546D",
  high: "#F2913D",
  medium: "#E7C548",
  low: "#4CC9A0",
};

// Tailwind text colour per severity/band.
export const severityText: Record<Severity, string> = {
  critical: "text-crit",
  high: "text-high",
  medium: "text-med",
  low: "text-low",
};

export const RISK_TYPE_LABEL: Record<RiskType, string> = {
  vulnerable: "Vulnerable (direct)",
  transitive_vuln: "Vulnerable (transitive)",
  license_conflict: "License conflict",
  unmaintained: "Unmaintained",
  clean: "Clean",
};

export const RISK_TYPE_HEX: Record<string, string> = {
  vulnerable: "#F0546D",
  transitive_vuln: "#F2913D",
  license_conflict: "#B47DFF",
  unmaintained: "#8A97B1",
};

export function bandLabel(band: Severity): string {
  return band.charAt(0).toUpperCase() + band.slice(1);
}
