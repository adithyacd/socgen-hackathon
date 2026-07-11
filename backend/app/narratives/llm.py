"""Thin, provider-swappable LLM wrapper with on-disk caching.

Design goals: the product runs fully WITHOUT a key (callers fall back to
deterministic templates), and every LLM call is cached so demos are fast,
cheap, and repeatable.
"""
from __future__ import annotations

import json
from typing import Optional

from ..config import settings


def _cache_path(key: str):
    return settings.cache_dir / f"{key}.json"


def cached(key: str) -> Optional[str]:
    p = _cache_path(key)
    if p.exists():
        try:
            return json.loads(p.read_text("utf-8"))["text"]
        except (ValueError, KeyError):
            return None
    return None


def store(key: str, text: str) -> None:
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    _cache_path(key).write_text(json.dumps({"text": text}), encoding="utf-8")


def llm_available() -> bool:
    return settings.llm_enabled


def llm_complete(
    system: str,
    user: str,
    *,
    max_tokens: int = 700,
    cache_key: Optional[str] = None,
) -> Optional[str]:
    """Return completion text, or None if no key / call failed (caller templates)."""
    if cache_key:
        hit = cached(cache_key)
        if hit is not None:
            return hit
    if not settings.llm_enabled:
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        msg = client.messages.create(
            model=settings.llm_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text").strip()
    except Exception:  # noqa: BLE001 — any failure falls back to templates
        return None
    if text and cache_key:
        store(cache_key, text)
    return text or None
