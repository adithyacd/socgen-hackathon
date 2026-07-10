import type { Severity } from "../api/types";
import { SEVERITY_HEX, bandLabel } from "../lib/risk";

export default function RiskMeter({
  score,
  band,
  size = "md",
}: {
  score: number;
  band: Severity;
  size?: "sm" | "md";
}) {
  const hex = SEVERITY_HEX[band];
  const h = size === "sm" ? "h-1.5" : "h-2";
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="font-mono text-[11px] uppercase tracking-widest text-mist">
          Risk {bandLabel(band)}
        </span>
        <span className="font-mono text-sm font-semibold" style={{ color: hex }}>
          {score.toFixed(0)}
          <span className="text-mist">/100</span>
        </span>
      </div>
      <div className={`w-full overflow-hidden rounded-full bg-panel2 ${h}`}>
        <div
          className={`${h} rounded-full transition-[width] duration-700`}
          style={{
            width: `${Math.max(3, Math.min(100, score))}%`,
            background: `linear-gradient(90deg, ${hex}88, ${hex})`,
          }}
        />
      </div>
    </div>
  );
}
