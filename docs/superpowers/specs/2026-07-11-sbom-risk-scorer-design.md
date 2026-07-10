# Sentinel — Software Supply Chain Risk Scorer (SBOM Analyzer)

**Design spec** · PB-10 · Société Générale PSG Hackathon
**Date:** 2026-07-11 · **Team size:** 1–2 · **Status:** Approved for planning

---

## 1. Context & problem

Enterprises run many applications, each pulling in dozens of open-source libraries.
When a critical vulnerability like Log4j (CVE-2021-44228) drops, security teams
cannot quickly answer: *which of our apps are exposed, through which (often nested,
transitive) dependency path, and is the vulnerable code even reachable?* Today this
takes ~40 hours of manual tracing per incident. Hidden risks compound: transitive
vulnerabilities, license conflicts (GPL in proprietary code), and unmaintained
libraries.

**PB-10 asks for** an automated SBOM analysis tool that ingests SBOMs, cross-references
a vulnerability database, resolves transitive dependency chains, checks license
compatibility, flags maintenance risk, scores per-application risk, and produces a
ranked remediation report.

## 2. Hackathon strategy (why this design wins)

Judging is on **"concepts, ideology, creativity & presentations"**, and the event is a
**recruiting funnel** (top teams get direct Société Générale interviews). Implications
baked into this design:

- **A finished, polished demo beats an ambitious half-built one.** Scope is disciplined.
- **Move up the value chain: detection → decision.** Most teams will build the literal
  brief (ingest → list CVEs → graph → score → PDF). We differentiate by answering
  *what's actually exploitable*, *the cheapest way to fix it*, and letting judges
  *talk to it*.
- **Prove it with real numbers.** An evaluation harness scores us against ground-truth
  labels so the pitch quotes measured accuracy — a credibility flex few teams have.
- **Bank framing.** Emphasize regulatory/audit/financial risk (post-Log4j/SolarWinds,
  supply-chain risk is board-level at every bank).

## 3. Goals / non-goals

**Goals**
- Deliver all 7 required capabilities (ingestion, vuln cross-ref, transitive resolution,
  license checking, maintenance risk, risk scoring, risk reporting).
- Deliver three signature differentiators: **reachability-aware exploitability**, a
  **Fix Optimizer**, and a **grounded Copilot**.
- Produce every deliverable from one codebase: live demo, slides, repo, recorded video,
  deployed URL.

**Non-goals**
- Real SBOM standard parsers (CycloneDX/SPDX) beyond a light adapter — synthetic data is
  the source of truth for the demo. (Adapter is a stretch, not a requirement.)
- Real registry/NVD API integration — the vulnerability DB is synthetic.
- Full static call-graph analysis — reachability is a faithful graph approximation
  (see §7), not compiler-grade analysis.

## 4. Product overview

**Name:** **Sentinel** — Supply Chain Risk Intelligence.
**One-line pitch:** *When the next Log4j drops, know which apps are exposed — and through
which hidden dependency path — in seconds, not 40 hours.*

**Signature feature — Zero-Day War Room:** a judge picks a CVE (or hits "Simulate Log4j")
and the dashboard instantly shows affected apps ranked by business criticality, the
transitive attack paths traced on a live graph, and an LLM-written incident brief +
remediation. This is the demo spine.

## 5. Architecture

```
  Synthetic dataset (SBOMs / Vuln DB / License rules / Labels)
        │
  [1] Ingestion & Normalization  → typed pydantic models
        │
  [2] Dependency Graph (NetworkX: App → Library → transitive deps, real edges)
        │
  [3] Analysis engines (each a pure function graph → findings):
        ├─ Vulnerability Matcher   (version-range aware CVE match)
        ├─ Transitive Resolver     (all paths app → vulnerable node)
        ├─ License Checker         (incompatibility matrix)
        ├─ Maintenance Checker     (stale / abandoned)
        ├─ Reachability            (Exploitable vs Present-but-unreachable)   ★
        └─ Fix Optimizer           (min upgrade set + what-if + conflicts)    ★
        │
  [4] Risk Scorer (contextual per-dependency + per-application)
        │
  [5] Narrative + Copilot layer (Claude): incident briefs, remediation,
        NL question → structured graph query → grounded answer            ★
        │
  [6] FastAPI (serves JSON) + static export (bulletproof deployed URL)
        │
  [7] React dashboard (6 views) + [8] Report exporter (PDF/HTML/CSV)
        │
  [E] Evaluation Harness — scores every engine vs ground-truth labels
```

Each engine is independently testable and reads only from the shared graph. ★ = differentiator.

## 6. Data model

Synthetic generator (`backend/tools/generate_data.py`) produces data mirroring the brief's
schema plus the fields our differentiators need. Risk mix matches the brief
(~18% vulnerable, ~12% license, ~15% unmaintained, ~10% transitive, ~45% clean).

| File | Rows | Key fields |
|---|---|---|
| `applications.json` | 10 | `app_id, name, business_criticality, owner, internet_facing, environment, ecosystem, license_context` |
| `dependencies.csv` | ~500 | `app_id, library, version, license, is_direct, parent, used, version_constraint, last_updated, maintainer_count` |
| `vulnerability_db.json` | ~200 | `cve_id, affected_library, version_range, cvss, severity, patch_available, fixed_version, vulnerable_symbol, kev, epss, published` |
| `license_rules.json` | ~15 | `license, category, incompatible_with[], risk_level` |
| `labels.csv` (ground truth) | ~500 | `app_id, library, is_risk, risk_type, severity, is_reachable, explanation` |

**Load-bearing fields:**
- `parent` → real graph edges (App → direct → transitive).
- `used` (per edge) + `vulnerable_symbol` (per CVE) → **reachability**.
- `fixed_version` + `version_constraint` → **Fix Optimizer** (and diamond-conflict detection).
- `internet_facing`, `business_criticality`, `kev`, `epss` → contextual risk scoring.

## 7. Dependency graph & engines

**Graph (NetworkX):** nodes = apps and `library@version`; edges = `depends_on` with
`{is_direct, used, version_constraint}`; CVEs overlay onto library nodes.

**Core engines**
1. **Vulnerability Matcher** — matches installed `library@version` against CVE
   `version_range` (semver-range aware, e.g. `>=2.0.0,<2.17.1`); not string equality.
2. **Transitive Resolver** — enumerates paths from each app to each vulnerable node;
   labels exposure direct vs. transitive; dedups multiple paths to the same node.
3. **License Checker** — each library's license vs. the app's `license_context` via the
   incompatibility matrix (flags e.g. GPL-in-proprietary), with severity by risk_level.
4. **Maintenance Checker** — stale (`last_updated` > 2 yrs) / abandoned (`maintainer_count` ≤ 1).

**Differentiator engines**
5. **Reachability** — a CVE is **Exploitable** iff a path exists from the app to the
   vulnerable library where **every edge has `used = true`**; otherwise
   **Present-but-unreachable**. This is the graph approximation of call-path reachability
   and is what slashes false positives.
6. **Fix Optimizer** — greedy **set-cover**: choose the minimum set of library upgrades
   (`fixed_version`) that eliminates the most weighted critical risk; report ordered plan
   and before/after risk; **what-if** recompute on version bump; flag **conflicts** when an
   upgrade violates a parent's `version_constraint` (diamond conflict).
7. **Copilot query layer** — Claude translates a natural-language question into a
   **structured query** over a small fixed schema (filters on app/library/license/severity/
   reachability/transitive), which we execute deterministically over the graph; Claude then
   explains the *real* result. Grounded — it reports data, it does not invent it.

## 8. Risk scoring

```
dep_risk = CVSS × reachability_factor × exploit_signal(KEV/EPSS) × depth_factor
           + license_penalty + maintenance_penalty
app_risk = aggregate(dep_risk) × business_criticality × internet_facing_factor
```
`reachability_factor` (unreachable → ~×0.15) is the lever that improves precision.
Scores normalize to 0–100 with severity bands for display.

## 9. Evaluation harness [E]

Runs every engine against `labels.csv` and prints a scorecard:
- Vulnerability detection rate (target > 85%)
- Transitive resolution (target 100%)
- License-conflict recall (target > 90%)
- **False-positive rate with vs. without reachability** (headline before/after slide; target < 20%)
- Risk-score accuracy vs. ground truth (target ±10%)

## 10. Dashboard — six views

1. **Portfolio Overview** — 10 app cards (risk gauge, criticality, internet-facing icon,
   top-risk summary), portfolio heatmap, headline *total exploitable criticals*; worst-first.
2. **App Detail + Dependency Graph** — Cytoscape: app center, direct→transitive deps,
   vulnerable nodes glow red, reachable paths bold, unreachable dimmed; filters
   (severity, reachable-only, license, stale).
3. **Zero-Day War Room** — CVE picker / "Simulate Log4j"; affected apps ranked by
   criticality, attack paths, LLM incident brief + remediation; timer
   (*"3.2s vs ~40 hrs manual"*).
4. **Fix Optimizer** — recommended upgrade set, before/after risk, what-if toggles with
   live recompute, conflict warnings.
5. **Copilot** — docked chat; grounded answers with evidence links into the graph.
6. **Accuracy** — our metrics vs. ground truth, incl. reachability FP before/after.

## 11. Tech stack

- **Backend:** Python 3.11, FastAPI, NetworkX, pandas, pydantic, uvicorn.
- **LLM:** Anthropic Claude via a thin provider interface (swappable); outputs **cached to
  disk** for fast, cheap, repeatable demos.
- **Frontend:** React + Vite + TypeScript, Tailwind, Cytoscape.js (graph), Recharts (charts).
- **Data:** Python synthetic generator.

## 12. Repo layout

```
SocieteGenerale/
  README.md
  docs/superpowers/specs/2026-07-11-sbom-risk-scorer-design.md
  data/                       # generated synthetic dataset
  backend/
    app/{ingestion,graph,engines,scoring,copilot,narratives,evaluation,export}/
    tools/generate_data.py
    tests/
    requirements.txt
  frontend/
    src/{views,components,api}/
    package.json
```

## 13. Deployment strategy

Analysis precomputes to a static `analysis.json` + cached narratives, so the deployed
dashboard runs **fully client-side and cannot break** during judging. The live FastAPI
backend powers full interactivity (live Copilot, what-if) for the local demo and video.
Deployed URL: static frontend (Vercel/Netlify/Pages); optional live backend
(Render/Railway) if we want live Copilot on the public URL.

## 14. Deliverables

- Working prototype (backend + dashboard) on synthetic data.
- Deployed public URL (static, robust).
- Recorded demo video (scripted around the War Room).
- Slide deck (problem, approach, differentiators, live metrics, impact).
- GitHub repo with README, architecture doc (this spec), and setup instructions.
- Sample risk report (PDF/HTML) with ranked findings + remediation.

## 15. Success criteria (from the brief)

| Metric | Target |
|---|---|
| Vulnerability detection | > 85% |
| Transitive resolution | 100% |
| License conflict detection | > 90% |
| False positive rate | < 20% |
| Risk score accuracy | ±10% of ground truth |

## 16. Build plan (phased; compresses/expands to available time)

- **Phase 0 — Foundation:** scaffold repo, synthetic data generator, graph builder.
  *Milestone: graph loads.*
- **Phase 1 — Core + proof:** 4 core engines + risk scoring + evaluation harness with real
  metrics, served via API. *Milestone: it works and we can measure it.*
- **Phase 2 — Differentiators:** reachability, Fix Optimizer, Copilot query layer + LLM
  narratives.
- **Phase 3 — Experience:** React dashboard (all six views), polish.
- **Phase 4 — Deliverables:** static export + deploy, PDF report, slides, demo video,
  README, rehearse. *Buffer for slippage.*

## 17. Risks & mitigations

- **LLM flakiness in live demo** → cache narratives to disk; Copilot answers grounded in
  deterministic graph queries; static export never depends on a live LLM call.
- **Scope creep** → core (Phase 1) is fully demoable on its own; differentiators are
  additive; deliverables phase has buffer.
- **Data realism** → synthetic generator tuned to the brief's risk distribution and
  seeded with a recognizable Log4j-style scenario for the War Room.
- **Deploy fragility** → static, client-side deployed build as the primary public URL.

## 18. Locked decisions

- Problem: **PB-10**. Approach: graph-based core + all three differentiators.
- Data: **synthetic** (schema-faithful); real `sample_data/` swappable later if obtained.
- LLM: **Claude**, provider-swappable, cached.
- Deliverables: live demo + slides + repo + video + deployed URL (all).
