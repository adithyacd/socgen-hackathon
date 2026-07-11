"""Sentinel FastAPI backend.

Computes the analysis context once at startup (data is static) and serves it to
the dashboard. Endpoints grow slice by slice.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .analysis import build_context
from .graphview import build_app_graph
from .schemas import AnalysisResult, AppGraph, WarRoomCve, WarRoomImpact
from .warroom import notable_cves, war_room_impact

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
    return impact
