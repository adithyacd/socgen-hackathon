"""Sentinel FastAPI backend.

Computes the analysis once at startup (data is static) and serves it to the
dashboard. Later slices add graph / war-room / optimizer / copilot endpoints.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .analysis import run_analysis
from .schemas import AnalysisResult

app = FastAPI(title="Sentinel — Supply Chain Risk Intelligence", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # DEMO-STUB: wide-open CORS is fine for a local hackathon demo
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compute once and cache in memory.
_ANALYSIS: AnalysisResult = run_analysis()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "apps": _ANALYSIS.summary.app_count}


@app.get("/api/analysis", response_model=AnalysisResult)
def analysis() -> AnalysisResult:
    return _ANALYSIS
