"""Runtime settings, loaded from environment / .env."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Repo root = two levels up from this file (backend/app/config.py -> repo root).
REPO_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(REPO_ROOT / "backend" / ".env")


class Settings:
    """Plain settings object (no heavy framework needed for a hackathon)."""

    def __init__(self) -> None:
        self.anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.llm_model: str = os.getenv("SENTINEL_LLM_MODEL", "claude-sonnet-4-5").strip()
        data_dir = os.getenv("SENTINEL_DATA_DIR", "data").strip()
        self.data_dir: Path = (REPO_ROOT / data_dir).resolve()
        self.cache_dir: Path = self.data_dir / "cache"

    @property
    def llm_enabled(self) -> bool:
        return bool(self.anthropic_api_key)


settings = Settings()
