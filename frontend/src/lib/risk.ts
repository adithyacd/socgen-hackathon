import type { RiskType, Severity } from "../api/types";

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#E60028", // the landing's ember red — danger, everywhere
  high: "#F2733B",
  medium: "#D9A441",
  low: "#45B08A",
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
  vulnerable: "#E60028",
  transitive_vuln: "#F2733B",
  license_conflict: "#79808F",
  transitive_license_conflict: "#79808F",
  license_unknown: "#79808F",
  unmaintained: "#8A8A93",
};

export const EXPLOIT_HEX: Record<string, string> = {
  high: "#E60028",
  medium: "#F2733B",
  low: "#D9A441",
  none: "#8A8A93",
};

export function bandLabel(band: Severity): string {
  return band.charAt(0).toUpperCase() + band.slice(1);
}

export function titleCase(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
