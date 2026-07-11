import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Sparkles, Send, Database, CornerDownLeft } from "lucide-react";
import { askCopilot, fetchCopilotSuggestions } from "../api/client";
import type { CopilotAnswer } from "../api/types";
import { severityText } from "../lib/risk";

function QueryChips({ query }: { query: Record<string, any> }) {
  const entries = Object.entries(query);
  if (!entries.length) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {entries.map(([k, v]) => (
        <span key={k} className="rounded bg-panel2 px-1.5 py-0.5 font-mono text-[10px] text-mist">
          {k}={String(v)}
        </span>
      ))}
    </div>
  );
}

function AnswerCard({ a }: { a: CopilotAnswer }) {
  return (
    <div className="card p-4">
      <div className="text-sm font-medium text-mist">{a.question}</div>
      <div className="mt-2 text-[15px] text-paper">{a.answer}</div>
      <div className="mt-2 flex items-center gap-2">
        <span className="inline-flex items-center gap-1 rounded-md bg-info/10 px-2 py-0.5 text-[10px] font-semibold text-info">
          <Database size={11} /> grounded · {a.match_count} real matches · via {a.source}
        </span>
      </div>
      <QueryChips query={a.query} />
      {a.matches.length > 0 && (
        <div className="mt-3 max-h-56 overflow-y-auto rounded-lg border border-line">
          <table className="w-full text-left text-xs">
            <tbody>
              {a.matches.map((m, i) => (
                <tr key={i} className="border-b border-line/60 last:border-0">
                  <td className="px-3 py-1.5">
                    <Link to={`/app/${m.app_id}`} className="text-paper hover:text-signal">
                      {m.app}
                    </Link>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-mist">{m.library}</td>
                  <td className="px-3 py-1.5">
                    {m.severity && <span className={severityText[m.severity]}>{m.severity}</span>}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-[10px] text-mist">
                    {m.cves?.slice(0, 2).join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function Copilot() {
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [llm, setLlm] = useState(false);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<CopilotAnswer[]>([]);
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchCopilotSuggestions()
      .then((s) => {
        setSuggestions(s.suggestions);
        setLlm(s.llm_enabled);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  async function ask(q: string) {
    const question = q.trim();
    if (!question || busy) return;
    setBusy(true);
    setInput("");
    try {
      const a = await askCopilot(question);
      setHistory((h) => [...h, a]);
    } catch (e) {
      setHistory((h) => [
        ...h,
        { question, answer: `Error: ${String(e)}`, query: {}, matches: [], match_count: 0, source: "rules" },
      ]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto flex h-[calc(100vh-4rem)] max-w-3xl flex-col md:h-[calc(100vh-2rem)]">
      <header className="mb-4">
        <div className="eyebrow flex items-center gap-1.5">
          <Sparkles size={13} /> Copilot
        </div>
        <h1 className="mt-1 font-display text-3xl font-bold tracking-tight text-paper">
          Ask your supply chain
        </h1>
        <p className="mt-1 max-w-2xl text-sm text-mist">
          Questions become a structured query executed over the real dependency graph — the
          copilot explains results, it never invents them.{" "}
          <span className="font-mono text-[11px] text-mist/80">
            {llm ? "LLM parsing enabled." : "Running on the keyword parser (no API key set)."}
          </span>
        </p>
      </header>

      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto pr-1">
        {history.length === 0 && (
          <div className="card grid place-items-center p-10 text-center">
            <Sparkles className="text-mist/40" size={36} />
            <p className="mt-3 text-sm text-mist">Try a question below, or ask your own.</p>
          </div>
        )}
        {history.map((a, i) => (
          <AnswerCard key={i} a={a} />
        ))}
        <div ref={endRef} />
      </div>

      {/* suggestions */}
      <div className="mt-3 flex flex-wrap gap-2">
        {suggestions.map((s) => (
          <button
            key={s}
            onClick={() => ask(s)}
            disabled={busy}
            className="rounded-full border border-line bg-panel px-3 py-1.5 text-xs text-mist transition-colors hover:border-signal/40 hover:text-paper disabled:opacity-50"
          >
            {s}
          </button>
        ))}
      </div>

      {/* input */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          ask(input);
        }}
        className="mt-3 flex items-center gap-2"
      >
        <div className="flex flex-1 items-center gap-2 rounded-xl border border-line bg-panel px-3 py-2 focus-within:border-signal/40">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Which internet-facing apps have exploitable criticals?"
            className="flex-1 bg-transparent text-sm text-paper placeholder:text-mist/50 focus:outline-none"
          />
          <CornerDownLeft size={14} className="text-mist/40" />
        </div>
        <button
          type="submit"
          disabled={busy || !input.trim()}
          className="grid h-10 w-10 place-items-center rounded-xl bg-signal text-ink transition-transform hover:scale-105 disabled:opacity-40"
        >
          <Send size={16} />
        </button>
      </form>
    </div>
  );
}
