# Sentinel — Demo Script, Slides & Judge Prep

## The 2‑minute demo (problem → demo → wow → impact)

**0:00 — The hook (Portfolio).**
"A dev team runs 10 apps, each pulling 50+ open‑source libraries. When Log4j dropped,
nobody could answer *which apps are exposed* for days. This is Sentinel." Land on the
Portfolio: 10 apps ranked worst‑first, **payments‑gateway** on top, the big red
*exploitable criticals* number.

**0:25 — The signature moment (War Room).**
Click **War Room → "Simulate top zero-day."** Watch the timer: "Portfolio resolved in ~0.4
seconds — manual tracing takes ~40 hours." Show the affected apps ranked exploitable-first,
the traced transitive attack path, and the LLM incident brief.

**0:55 — The differentiator (App graph + exploitability).**
Open the worst app. The dependency constellation: red vulnerable nodes, traced paths,
**dimmed = lower-exploitability**. "We flag every vulnerable dependency for completeness —
but we rank by the CVE's *real exploitability*, so the analyst sees the HIGH/MEDIUM ones
first, not a wall of noise."

**1:20 — The decision (Fix Optimizer).**
"Don't just tell me I'm on fire — tell me how to put it out." The optimizer: the minimum set
of shared-library upgrades that removes the most exploitable risk, with **diamond-conflict**
detection when an upgrade breaks a dependent's version pin.

**1:40 — The proof (Accuracy) + copilot.**
Accuracy page: "scored on the official 500-dependency benchmark — **91% detection recall**,
**100% on license and maintenance**." Mention the rigor flex: "we even found their vuln
labels are version-inconsistent with the DB." Then Copilot: *"Which internet-facing apps
have exploitable criticals?"* — grounded in the real graph, with the structured query shown.

**1:58 — Close.**
"Detection is the easy part — a lookup. The hard, valuable part is telling you what's
*actually exploitable* and the cheapest way to fix it. That's Sentinel."

---

## Slide outline (7 slides)

1. **Title** — Sentinel · *When the next Log4j drops, know who's exposed in seconds.*
2. **Problem** — Log4Shell chaos: no inventory, transitive blindness, 40 hrs/incident, license & maintenance risk. (Bank framing: audit, regulatory, financial exposure.)
3. **Approach** — SBOM → dependency graph → 6 engines → contextual risk. One diagram.
4. **Differentiators** — Reachability · Fix Optimizer · Grounded Copilot · Zero‑Day War Room.
5. **Live demo** — (switch to the app; War Room is the spine.)
6. **Proof** — official 500-dependency benchmark: 91% detection recall, 100% license + maintenance; exploitability prioritization surfaces the ~70% actionable set.
7. **Impact & roadmap** — 40 hrs → seconds; real SBOM (CycloneDX/SPDX) + live NVD/registry feeds; static call-graph reachability next.

---

## Judge Q&A prep

**"How well do you score on the provided benchmark?"**
We ingest the official `dependency_labels.csv` and hit **91% overall detection recall** with
**100% on license and maintenance**. Vulnerability precision is bounded by *their* data: we
found the provided vulnerability labels are version-inconsistent with the vulnerability DB
(e.g. `log4j-api 4.8.3` is inside a CVE's affected range yet labeled clean). We detect every
vulnerable library via the standard below-fixed-version rule and report honestly — then use
each CVE's real **exploitability** to prioritize the ~70% that are actually actionable.

**"How would this work on real data / at scale?"**
The engines are pure functions over a NetworkX graph; swapping the synthetic loader for a
CycloneDX/SPDX parser and a live NVD + registry feed is a data‑source change, not an
architecture change. Reachability today uses a used‑edge model; in production it upgrades to
static call‑graph analysis (à la Endor/Semgrep) behind the same interface.

**"PII / security of the tool itself?"**
Sentinel reads dependency metadata, not source or secrets. The LLM layer only *parses*
questions into a constrained query we execute deterministically and only *phrases* results
computed from real data — it can't exfiltrate or invent. It's also fully optional; the
product runs with no external API at all.

---

## Fallback (if live fails)

Deploy the static build (`dist/`) — it runs entirely client‑side and can't break. Have
`dist/report.html` (the printed risk report) and a screen recording of the War Room ready.
