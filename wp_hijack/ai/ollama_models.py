"""Ollama model utilities — list, fetch info, verify connectivity."""
from __future__ import annotations
import asyncio
from typing import Any


async def fetch_ollama_models(base_url: str = "http://localhost:11434", timeout: int = 10) -> list[dict]:
    """
    Query Ollama /api/tags and return a list of model dicts.

    Each dict contains at minimum:
      name, size, modified_at, digest, details (family, parameter_size, quantization_level)

    Raises ConnectionError if Ollama is unreachable.
    """
    import httpx
    url = base_url.rstrip("/") + "/api/tags"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            return data.get("models", [])
    except httpx.ConnectError:
        raise ConnectionError(
            f"Cannot connect to Ollama at {base_url}\n"
            "Make sure Ollama is running:  ollama serve"
        )
    except httpx.TimeoutException:
        raise ConnectionError(f"Ollama at {base_url} timed out after {timeout}s")
    except Exception as exc:
        raise ConnectionError(f"Ollama model fetch failed: {exc}")


def format_size(size_bytes: int) -> str:
    """Human-readable model size."""
    if size_bytes >= 1_000_000_000:
        return f"{size_bytes / 1_000_000_000:.1f} GB"
    elif size_bytes >= 1_000_000:
        return f"{size_bytes / 1_000_000:.0f} MB"
    return f"{size_bytes} B"


def get_ollama_base_url(cfg: dict) -> str:
    """Extract Ollama base_url from config, falling back to default."""
    # Check ollama-specific section first, then ai.base_url
    ollama_cfg = cfg.get("ollama", {})
    if ollama_cfg.get("base_url"):
        return ollama_cfg["base_url"].rstrip("/").replace("/v1", "")
    ai_base = cfg.get("ai", {}).get("base_url") or ""
    if ai_base:
        return ai_base.rstrip("/").replace("/v1", "")
    return "http://localhost:11434"
