# Sentinel — Implementation Plan

> **Execution mode:** Full autonomous build, no approval gates. One commit per working
> vertical slice. Conventional-commit prefixes. No AI identity in commits.

**Goal:** Build Sentinel — an SBOM supply-chain risk scorer (PB-10) with reachability
analysis, a fix optimizer, a grounded LLM copilot, and a Zero-Day War Room demo.

**Architecture:** Python/FastAPI backend loads synthetic SBOM data into a NetworkX
dependency graph; pure-function engines (vuln, transitive, license, maintenance,
reachability, optimizer) produce findings; a scorer ranks per-app risk; a Claude layer
writes narratives and powers a grounded copilot. React/Vite/Cytoscape frontend renders six
views. Analysis precomputes to a static `analysis.json` so the deployed build runs
client-side.

**Tech Stack:** Python 3.11+, FastAPI, NetworkX, pandas, pydantic, anthropic, pytest;
React + Vite + TypeScript, Tailwind, Cytoscape.js, Recharts.

## Global Constraints

- Synthetic data only; schema-faithful to the PB-10 brief; risk mix ~18% vuln / 12%
  license / 15% unmaintained / 10% transitive / 45% clean. Seeded (`random.seed(42)`) for reproducibility.
- Success targets: vuln detection >85%, transitive resolution 100%, license >90%, FP <20%, risk score ±10%.
- TDD only on core-correctness code (engines, scoring, optimizer, copilot query). Not on UI glue / stubs.
- Every demo shortcut tagged `# DEMO-STUB`. Secrets in `.env`; provide `.env.example`.
- Commits: conventional prefix, no `Co-Authored-By`, no AI mention. Author: personal identity (repo-local).

## File structure

```
backend/
  app/
    models.py              # pydantic domain models
    config.py              # settings (.env)
    data/loader.py         # load synthetic files -> models
    graph/builder.py       # models -> NetworkX graph
    engines/vuln.py transitive.py license.py maintenance.py reachability.py optimizer.py
    scoring/score.py       # per-dependency + per-app risk
    narratives/llm.py      # Claude provider (cached)
    copilot/query.py       # NL -> structured graph query -> answer
    evaluation/evaluate.py # vs ground-truth labels
    export/static_export.py# write analysis.json
    analysis.py            # orchestrate load->graph->engines->score-> result
    main.py                # FastAPI app + endpoints
  tools/generate_data.py   # synthetic dataset generator
  tests/                   # pytest
  requirements.txt  .env.example
frontend/
  src/
    api/client.ts          # fetch analysis (static json or live API)
    views/{Portfolio,AppDetail,WarRoom,Optimizer,Copilot,Accuracy}.tsx
    components/  App.tsx  main.tsx  index.css
  package.json  vite/ts/tailwind config
data/                      # generated dataset (gitignored except a committed sample)
```

## Vertical slices (each is end-to-end demoable and gets its own commit)

### Slice 0 — Scaffold + synthetic data  →  `chore:` / `feat:`
Backend project skeleton, `requirements.txt`, `.env.example`, pydantic models, and the
data generator emitting `applications.json`, `dependencies.csv`, `vulnerability_db.json`,
`license_rules.json`, `labels.csv`. **Demo:** running the generator writes the 5 files;
models load them without error. **TDD:** generator output invariants (counts, risk mix, a
seeded Log4j scenario present).

### Slice 1 — Core detection spine  →  `feat:`
Loader → graph builder → **vulnerability matcher** (semver-range aware) → **scorer** →
`analysis.py` orchestrator → FastAPI `/api/analysis` → minimal React **Portfolio** view.
**Demo:** browser shows 10 apps ranked by risk with vuln counts. **TDD:** version-range
matcher, scorer.

### Slice 2 — Dependency graph + transitive  →  `feat:`
**Transitive resolver** (all paths app→vulnerable node; direct vs transitive). **AppDetail**
view with Cytoscape graph (vulnerable nodes red, transitive paths highlighted). **Demo:**
click an app → interactive graph. **TDD:** transitive path enumeration + dedup.

### Slice 3 — License + maintenance  →  `feat:`
**License checker** (incompatibility matrix) + **maintenance checker** (stale/abandoned),
folded into findings and scoring. **Demo:** findings list shows license conflicts + stale
libs; portfolio scores update. **TDD:** license matrix, staleness thresholds.

### Slice 4 — Reachability + evaluation  →  `feat:`
**Reachability engine** (Exploitable iff a path exists with every edge `used=true`);
Exploitable/Unreachable badges. **Evaluation harness** vs `labels.csv`. **Accuracy** view
showing FP rate with vs without reachability + all target metrics. **Demo:** Accuracy page
proves the numbers. **TDD:** reachability rule, evaluation metrics.

### Slice 5 — Zero-Day War Room  →  `feat:`
Cross-app CVE impact query + **WarRoom** view ("Simulate Log4j" / CVE picker): affected
apps ranked by business criticality, attack paths, response timer. **Demo:** one click →
portfolio-wide impact.

### Slice 6 — Fix Optimizer  →  `feat:`
**Set-cover optimizer** (min upgrade set killing most weighted critical risk) + what-if
recompute + version-constraint conflict detection. **Optimizer** view with before/after +
toggles. **Demo:** recommended upgrades, live recompute. **TDD:** set-cover, conflicts.

### Slice 7 — LLM narratives + grounded copilot  →  `feat:`
**Claude provider** (disk-cached, provider-swappable) writing incident briefs +
remediation; **copilot** turns NL questions into a fixed structured query executed over the
graph, then explains real results. **Copilot** view. **Demo:** War Room brief + a live
grounded answer. **TDD:** copilot query parse/execute (deterministic path); LLM mocked.

### Slice 8 — Reports, static export, deploy, deliverables  →  `feat:` / `docs:`
Static export (`analysis.json` + cached narratives) so the SPA runs client-side; HTML/PDF
risk report; `README.md`; deploy config; slide/demo-script outline. **Demo:** static build
served with no backend; report exports.

## Self-review (spec coverage)

Every PB-10 requirement maps to a slice: ingestion (0/1), vuln cross-ref (1), transitive (2),
license (3), maintenance (3), risk scoring (1,3,4), reporting (8); differentiators:
reachability (4), war room (5), optimizer (6), copilot (7); evaluation harness (4);
deliverables (8). No gaps.
