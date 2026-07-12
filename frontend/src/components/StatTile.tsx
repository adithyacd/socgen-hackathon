import type { ReactNode } from "react";

export default function StatTile({
  label,
  value,
  sub,
  accent,
  icon,
}: {
  label: string;
  value: ReactNode;
  sub?: string;
  accent?: string; // hex for the value
  icon?: ReactNode;
}) {
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between">
        <span className="eyebrow">{label}</span>
        {icon && <span className="text-mist">{icon}</span>}
      </div>
      <div
        className="mt-2 font-display text-3xl font-bold tracking-tight"
        style={{ color: accent ?? "#F4F4F5" }}
      >
        {value}
      </div>
      {sub && <div className="mt-1 text-xs text-mist">{sub}</div>}
    </div>
  );
}
