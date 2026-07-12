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
  transitive_license_conflict: "License conflict (transitive)",
  license_unknown: "Unknown license",
  unmaintained: "Unmaintained",
  clean: "Clean",
};

export const RISK_TYPE_HEX: Record<string, string> = {
  vulnerable: "#F0546D",
  transitive_vuln: "#F2913D",
  license_conflict: "#B47DFF",
  transitive_license_conflict: "#9A6BFF",
  license_unknown: "#7C8AA8",
  unmaintained: "#8A97B1",
};

export const EXPLOIT_HEX: Record<string, string> = {
  high: "#F0546D",
  medium: "#F2913D",
  low: "#E7C548",
  none: "#8A97B1",
};

export function bandLabel(band: Severity): string {
  return band.charAt(0).toUpperCase() + band.slice(1);
}

export function titleCase(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
