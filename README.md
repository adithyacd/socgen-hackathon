# Sentinel — Software Supply Chain Risk Scorer

> When the next Log4j drops, know which of your apps are exposed — and through which
> hidden dependency path — in **seconds, not 40 hours.**

Sentinel is a Software Bill of Materials (SBOM) risk analyzer built for the Société
Générale PSG Hackathon (problem statement **PB‑10**). It ingests dependency data across a
portfolio of applications, resolves transitive dependency chains, cross‑references known
vulnerabilities, checks licenses and maintenance signals, and scores per‑application
supply‑chain risk.

Most tools stop at *a list of CVEs*. Sentinel is a **decision engine**: it tells you what
is **actually exploitable**, the **cheapest way to fix it**, and lets you **ask it questions**.

---

## What makes it different

| | Everyone builds | Sentinel adds |
|---|---|---|
| Detection | List matching CVEs | **Reachability analysis** — is the vulnerable code actually on a used call path? |
| Prioritization | Sort by CVSS | **Contextual risk** — reachability × exploit signal (KEV/EPSS) × business criticality × internet exposure |
| Remediation | "You have N criticals" | **Fix Optimizer** — the minimum set of upgrades that removes the most risk, with diamond‑conflict detection |
| Interaction | Static report | **Grounded copilot** — ask in English, answered from the real graph (never hallucinated) |
| Demo | A dashboard | **Zero‑Day War Room** — one click traces a CVE's blast radius across the whole portfolio |

### The reachability dividend (measured against ground‑truth labels)

- **100%** of known CVEs detected · **100%** transitive resolution · **100%** license‑conflict detection
- Vulnerability‑alert precision: **69% → 100%** once unreachable vulns are suppressed
- False‑positive rate: **5% → 0%**
- **31%** of vulnerability alerts eliminated as noise (they're present but never called)

The insight: a large share of *transitive* vulnerabilities are never actually executed.
Naive scanners drown teams in them; Sentinel filters them out and proves the difference on
the **Accuracy** page.

---

## Quick start

Requires Python 3.11+ and Node 18+.

```bash
# 1. Backend
python -m venv .venv
.venv/Scripts/activate           # Windows:  .venv\Scripts\activate   |  macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt
python -m backend.tools.generate_data          # writes the synthetic dataset to data/
uvicorn backend.app.main:app --reload --port 8000

# 2. Frontend (separate terminal)
cd frontend
npm install
npm run dev                                     # http://localhost:5173
```

Open **http://localhost:5173**. The dashboard talks to the API on port 8000.

### Optional: LLM narratives + copilot

Everything works **without an API key** (deterministic templates + a keyword parser). To
enable Claude‑written incident briefs and LLM question parsing, copy `backend/.env.example`
to `backend/.env` and set `ANTHROPIC_API_KEY`. Results are cached to `data/cache/`.

### Static build (bulletproof deployed URL)

```bash
python -m backend.tools.build_static     # precompute every API response into frontend/public/
cd frontend && npm run build             # dist/ is a fully self-contained static site
```

`dist/` runs entirely client‑side (no backend needed) — deploy it to any static host
(Vercel, Netlify, GitHub Pages). A print‑ready risk report is generated at `dist/report.html`.

---

## Architecture

```
  Synthetic SBOM data (apps, dependencies, vuln DB, license rules, ground-truth labels)
        │
   Ingestion → typed models → NetworkX dependency graph (per-app namespaced)
        │
   Engines (pure functions over the graph):
     vuln · transitive · license · maintenance · reachability · fix-optimizer
        │
   Contextual risk scoring  →  per-dependency + per-application (0–100)
        │
   LLM layer (optional, cached): incident narratives · grounded copilot query
        │
   FastAPI  ──────────────►  React + Cytoscape dashboard (6 views)
        │                         Portfolio · App graph · War Room · Optimizer · Copilot · Accuracy
   Static export ──────────►  self-contained dist/ + HTML report
        │
   Evaluation harness  →  scores every engine vs. ground-truth labels
```

## Project structure

```
backend/app/
  models.py schemas.py analysis.py       # domain models, API schemas, orchestrator
  data/ graph/                           # loader + NetworkX builder/traversal
  engines/                               # vuln, transitive, license, maintenance, reachability
  scoring/ evaluation/                   # risk scoring, accuracy harness
  optimizer.py warroom.py graphview.py   # differentiators + per-view builders
  copilot/ narratives/                   # grounded copilot + LLM layer (optional key)
  tools/generate_data.py build_static.py # synthetic data + static export
backend/tests/                           # 34 tests (engines, scoring, eval, war room, optimizer, copilot)
frontend/src/
  views/ components/ api/ lib/           # React dashboard
data/                                    # generated synthetic dataset
docs/superpowers/                        # design spec + implementation plan + demo script
```

## Tech stack

**Backend** Python · FastAPI · NetworkX · pandas · pydantic · Anthropic Claude (optional) ·
pytest
**Frontend** React · Vite · TypeScript · Tailwind · Cytoscape.js · Recharts

## Data

The dataset is **synthetic** and generated with a fixed seed for reproducibility
(`backend/tools/generate_data.py`), faithful to the PB‑10 schema and risk distribution. It
includes a planted **Log4Shell** scenario reaching four applications through different
transitive paths, with reachability deliberately varied so two apps are exploitable and two
are present‑but‑unreachable — the core of the reachability story.

## Tests

```bash
python -m pytest backend/tests -q        # 34 passing
```

---

*Société Générale PSG Hackathon · PB‑10 · Sentinel.*
