import { Loader2, WifiOff } from "lucide-react";

export function Loading({ label = "Analyzing supply chain…" }: { label?: string }) {
  return (
    <div className="grid min-h-[60vh] place-items-center text-mist">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="animate-spin text-signal" size={28} />
        <span className="font-mono text-sm">{label}</span>
      </div>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="grid min-h-[60vh] place-items-center">
      <div className="card max-w-lg p-8 text-center">
        <WifiOff className="mx-auto text-crit" size={28} />
        <h2 className="mt-3 font-display text-xl font-bold text-paper">Can’t reach the analysis API</h2>
        <p className="mt-2 text-sm text-mist">
          Start the backend, then reload:
          <code className="mt-2 block rounded-md bg-panel2 px-3 py-2 text-left font-mono text-xs text-paper">
            uvicorn backend.app.main:app --reload
          </code>
        </p>
        <p className="mt-3 font-mono text-[11px] text-mist/70">{message}</p>
      </div>
    </div>
  );
}
