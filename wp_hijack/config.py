"""Configuration loader — reads config.json and provides typed access."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# Bundled defaults — used when no config.json is found on disk
_BUNDLED_DEFAULTS: dict[str, Any] = {
    "tool": {
        "name": "wp-Hijack",
        "version": "1.0.0",
        "author": "KDO || Xpert Exploit",
        "github": "github.com/kdo2064/wp-Hijack",
    },
    "ai": {
        "enabled": True,
        "provider": "ollama",
        "api_key": "ollama",
        "model": "minimaxai/minimax-m2.5",
        "max_tokens": 4096,
        "temperature": 0.2,
        "base_url": "http://localhost:11434/v1",
        "timeout": 180,
        "max_retries": 3,
    },
    "ollama": {
        "base_url": "http://localhost:11434",
        "default_model": "minimaxai/minimax-m2.5",
        "timeout": 180,
        "context_size": 4096,
    },
    "scanner": {
        "threads": 10,
        "timeout": 15,
        "user_agent_rotation": True,
        "stealth_mode": False,
        "delay_between_requests": 0.0,
        "proxy": None,
        "verify_ssl": False,
    },
    "confirmation": {
        "run_confirmations": True,
        "allow_cautious_tests": False,
        "confirmation_timeout": 10,
    },
    "exploit": {
        "auto_generate": True,
        "auto_generate_severity": ["CRITICAL", "HIGH"],
        "interactive_prompt": True,
        "save_to_report": True,
    },
    "vulndb": {
        "auto_update": True,
        "update_check_hours": 24,
        "wpvulnerability_api": True,
    },
    "reporting": {
        "pdf_enabled": True,
        "html_enabled": True,
        "json_enabled": True,
        "markdown_enabled": False,
    },
}


def _find_config() -> Path | None:
    """
    Search for config.json in priority order:
      1. Current working directory  (./config.json)
      2. User home dir              (~/.wp-hijack/config.json)
      3. Next to the package source (only works in dev/editable installs)
    """
    candidates = [
        Path.cwd() / "config.json",
        Path.home() / ".wp-hijack" / "config.json",
        Path(__file__).parent.parent / "config.json",  # dev/editable install
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """
    Load config.json as a dict.

    Resolution order when no explicit path is given:
      1. cwd/config.json
      2. ~/.wp-hijack/config.json
      3. Project root config.json  (only for editable/dev installs)
      4. Built-in defaults         (never raises — works after pip install)
    """
    if path:
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"config.json not found at {config_path}")
        with open(config_path, encoding="utf-8") as fh:
            return json.load(fh)

    found = _find_config()
    if found:
        with open(found, encoding="utf-8") as fh:
            return json.load(fh)

    # No config.json found anywhere — return built-in defaults silently
    return dict(_BUNDLED_DEFAULTS)


def get_ai_config(cfg: dict) -> dict:
    return cfg.get("ai", {})


def get_scanner_config(cfg: dict) -> dict:
    return cfg.get("scanner", {})


def get_exploit_config(cfg: dict) -> dict:
    return cfg.get("exploit", {})


def get_confirmation_config(cfg: dict) -> dict:
    return cfg.get("confirmation", {})


def get_tool_meta(cfg: dict) -> dict:
    return cfg.get("tool", {
        "name":    "wp-Hijack",
        "version": "1.0.0",
        "author":  "KDO || Xpert Exploit",
        "github":  "github.com/kdo2064/wp-Hijack",
    })


def is_ai_enabled(cfg: dict) -> bool:
    return cfg.get("ai", {}).get("enabled", True)


def is_pdf_enabled(cfg: dict) -> bool:
    return cfg.get("reporting", {}).get("pdf_enabled", True)
