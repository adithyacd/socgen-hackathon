# Sentinel — Demo Script, Slides & Judge Prep

## The 2‑minute demo (problem → demo → wow → impact)

**0:00 — The hook (Portfolio).**
"A dev team runs 10 apps, each pulling 50+ open‑source libraries. When Log4j dropped,
nobody could answer *which apps are exposed* for days. This is Sentinel." Land on the
Portfolio: 10 apps ranked worst‑first, **payments‑gateway** on top, the big red
*exploitable criticals* number.

**0:25 — The signature moment (War Room).**
Click **War Room → "Simulate Log4Shell."** Watch the timer: "Portfolio resolved in ~0.4
seconds — manual tracing takes ~40 hours." Four apps carry the vulnerable library; only
**two are actually exploitable**. Point at the traced attack path
`app → spring-boot-starter → enterprise-logging → log4j-core` and the LLM incident brief.

**0:55 — The differentiator (App graph + reachability).**
Open **payments‑gateway**. The dependency constellation: red vulnerable nodes, bold used
paths, **dashed = code path not exercised**. "loan‑origination has the *same* Log4j version —
but it's unreachable, so we suppress it. That's the difference between 40 alerts and the 2
that matter."

**1:20 — The decision (Fix Optimizer).**
"Don't just tell me I'm on fire — tell me how to put it out." The optimizer: upgrade a
handful of shared libraries to kill most criticals. Toggle **log4j‑core → 2.17.1** and show
the **diamond conflict**: `enterprise-logging` pins `<2.16.0`, so you must bump it too.

**1:40 — The proof (Accuracy) + copilot.**
Accuracy page: "measured against ground truth — alert precision **69% → 100%**, **31%** of
alerts eliminated." Then Copilot: type *"Which internet‑facing apps have exploitable
criticals?"* — answered from the real graph, grounded, with the structured query shown.

**1:58 — Close.**
"Detection is easy; it's a lookup. The hard, valuable part is telling you what's *actually
exploitable* and the cheapest way to fix it. That's Sentinel."

---

## Slide outline (7 slides)

1. **Title** — Sentinel · *When the next Log4j drops, know who's exposed in seconds.*
2. **Problem** — Log4Shell chaos: no inventory, transitive blindness, 40 hrs/incident, license & maintenance risk. (Bank framing: audit, regulatory, financial exposure.)
3. **Approach** — SBOM → dependency graph → 6 engines → contextual risk. One diagram.
4. **Differentiators** — Reachability · Fix Optimizer · Grounded Copilot · Zero‑Day War Room.
5. **Live demo** — (switch to the app; War Room is the spine.)
6. **Proof** — real metrics vs. ground truth: 100% detection, precision 69%→100%, 31% noise cut, FP 5%→0%.
7. **Impact & roadmap** — 40 hrs → seconds; ≥50% fewer manual reviews; real SBOM (CycloneDX/SPDX) + live NVD/registry feeds next.

---

## Judge Q&A prep

**"Isn't 100% detection just testing against your own labels?"**
Yes — detection of *known* CVEs is a database lookup, so recall should be complete; we're
honest that it's the easy part. The hard, differentiating metric is **precision**:
reachability lifts vulnerability‑alert precision from 69% to 100% and removes 31% of alerts
as unexploitable noise. That's the number that saves analyst time.

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
