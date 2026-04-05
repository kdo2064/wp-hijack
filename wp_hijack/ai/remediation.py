"""AI-generated remediation guides."""
from __future__ import annotations
from typing import Any
from .client import ask
from .exploit_prompts import build_remediation_prompt


async def generate_remediation(finding: Any, ai_config: dict) -> str:
    prompt = build_remediation_prompt(finding)
    try:
        return await ask(prompt, system="You are a WordPress security engineer writing remediation guides.", config=ai_config)
    except Exception as exc:
        return f"Remediation: Update {finding.component} to {finding.fixed_version or 'latest version'}. (AI unavailable: {exc})"
