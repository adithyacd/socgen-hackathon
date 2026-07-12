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
| Detection | List matching CVEs | **Exploitability prioritization** — rank by the CVE's real exploitability, not just CVSS |
| Prioritization | Sort by CVSS | **Contextual risk** — exploitability × severity × business criticality × internet exposure |
| Remediation | "You have N criticals" | **Fix Optimizer** — the minimum set of upgrades that removes the most risk, with diamond‑conflict detection |
| Interaction | Static report | **Grounded copilot** — ask in English, answered from the real graph (never hallucinated) |
| Demo | A dashboard | **Zero‑Day War Room** — one click traces a CVE's blast radius across the whole portfolio |

### Measured on the official SG benchmark (500 labeled dependencies)

Sentinel ingests the official PB‑10 sample data and scores against the provided
`dependency_labels.csv`:

- **91%** overall detection recall (target ≥ 85%) · **100%** license‑conflict & maintenance detection · **100%** exact match on those categories
- **Exploitability prioritization:** every vulnerable dependency is flagged, but only ~**70%** are HIGH/MEDIUM exploitability — the actionable set an analyst should triage first
- We also caught a **data‑quality issue in the provided labels** (their vulnerability labels are version‑inconsistent with the vuln DB); we detect every vulnerable library via the standard below‑fixed‑version rule and report honestly against the noisy labels

The **Accuracy** page shows all of this live. A richer *synthetic* dataset (with a planted
Log4Shell reachability scenario) is also included as an optional mode.

### Beyond the brief — four things most teams won't do

Anyone can build the SBOM scanner the brief describes. These break from it:

1. **Supply-chain threat hunting** (`Threats` + the threat engine) — the risks a CVE list
   *can't* see: **typosquatting** (Damerau distance-1, zero false positives on the official
   data), **dependency confusion** (public namesakes at implausible versions), and a
   **known-malicious feed** (event-stream, ua-parser-js, xz-utils…). This is the
   SolarWinds/xz attack axis the CVE-centric dataset ignores.
2. **Benchmark Integrity Auditor** (`Benchmark Audit`) — instead of blindly optimizing to
   the provided labels, we **audit them** and prove they're version-inconsistent with the
   vuln DB (42/100 integrity, with concrete evidence). A detector should be robust to a
   noisy benchmark, not overfit to it.
3. **Real SBOM ingestion** (`Scan SBOM`) — paste a real `package.json`, `requirements.txt`,
   or CycloneDX/SPDX file and analyze it live. It's a tool, not a demo.
4. **CI/CD policy gate** (`backend/cli.py` + `.github/workflows/supply-chain-gate.yml`) — a
   command that **fails a pull request** when a dependency change introduces supply-chain
   risk. Governance as code, for developers — not just a security dashboard.

```bash
python -m backend.cli examples/sample-sbom.cdx.json --policy sentinel-policy.json  # exits 1 on violation
```

---

## Quick start

Requires Python 3.11+ and Node 18+.

```bash
# 1. Backend
python -m venv .venv
.venv/Scripts/activate           # Windows:  .venv\Scripts\activate   |  macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload --port 8000   # uses the official benchmark data by default

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

**Primary (default): the official SG PB‑10 benchmark** in `data/official/` — 10 apps,
500 dependencies, a simulated NVD, license rules, transitive edges, and ground‑truth
`dependency_labels.csv`. Sentinel ingests this schema directly (`data/official_loader.py`)
and the **Accuracy** page scores against their labels.

**Optional: a synthetic dataset** (`backend/tools/generate_data.py`, fixed seed) with a
planted **Log4Shell** reachability scenario. Switch with `SENTINEL_DATASET=synthetic`
(after `python -m backend.tools.generate_data`). It demonstrates the used‑edge reachability
model that the official data — lacking a reachability field — replaces with real
exploitability ratings.

## Tests

```bash
python -m pytest backend/tests -q        # 34 passing
```

---

*Société Générale PSG Hackathon · PB‑10 · Sentinel.*
