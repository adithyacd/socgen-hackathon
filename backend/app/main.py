"""Sentinel FastAPI backend.

Computes the analysis context once at startup (data is static) and serves it to
the dashboard. Endpoints grow slice by slice.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .analysis import build_context
from .copilot.query import answer as copilot_answer
from .graphview import build_app_graph
from .narratives.incident import incident_brief
from .narratives.llm import llm_available
from .optimizer import build_fix_plan
from .schemas import (
    AnalysisResult,
    AppGraph,
    CopilotAnswer,
    CopilotRequest,
    FixPlan,
    WarRoomCve,
    WarRoomImpact,
)
from .warroom import notable_cves, war_room_impact

COPILOT_SUGGESTIONS = [
    "Which internet-facing apps have exploitable criticals?",
    "Show all GPL license conflicts",
    "Which apps are exposed to Log4Shell?",
    "List unmaintained libraries",
    "Which transitive dependencies are exploitable?",
]

app = FastAPI(title="Sentinel — Supply Chain Risk Intelligence", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # DEMO-STUB: wide-open CORS is fine for a local hackathon demo
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compute once and cache in memory.
CTX = build_context()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "apps": CTX.result.summary.app_count}


@app.get("/api/analysis", response_model=AnalysisResult)
def analysis() -> AnalysisResult:
    return CTX.result


@app.get("/api/apps/{app_id}/graph", response_model=AppGraph)
def app_graph(app_id: str) -> AppGraph:
    graph = build_app_graph(CTX, app_id)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"Unknown app: {app_id}")
    return graph


@app.get("/api/warroom/cves", response_model=list[WarRoomCve])
def warroom_cves() -> list[WarRoomCve]:
    return notable_cves(CTX)


@app.get("/api/warroom/impact/{cve_id}", response_model=WarRoomImpact)
def warroom_impact(cve_id: str) -> WarRoomImpact:
    impact = war_room_impact(CTX, cve_id)
    if impact is None:
        raise HTTPException(status_code=404, detail=f"Unknown CVE: {cve_id}")
    impact.narrative = incident_brief(impact)
    return impact


@app.get("/api/optimizer/plan", response_model=FixPlan)
def optimizer_plan() -> FixPlan:
    return build_fix_plan(CTX)


@app.get("/api/copilot/suggestions")
def copilot_suggestions() -> dict:
    return {"suggestions": COPILOT_SUGGESTIONS, "llm_enabled": llm_available()}


@app.post("/api/copilot/ask", response_model=CopilotAnswer)
def copilot_ask(req: CopilotRequest) -> CopilotAnswer:
    return copilot_answer(CTX, req.question)
