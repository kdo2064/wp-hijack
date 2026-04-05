"""AI risk scorer — overall risk posture for a scan."""

from __future__ import annotations

import json

import re

from typing import Any



from .client import ask

from .exploit_prompts import build_risk_prompt





async def score_risk(findings: list[Any], target: str, ai_config: dict) -> dict:

    if not findings:

        return {"score": 0, "summary": "No vulnerabilities detected."}

    prompt = build_risk_prompt(findings, target)

    try:

        response = await ask(prompt, system="You are a professional security risk analyst. Respond only with valid JSON.", config=ai_config)


        m = re.search(r"\{.*\}", response, re.S)

        if m:

            return json.loads(m.group(0))

        return {"raw": response}

    except Exception as exc:

        return {"error": str(exc)}

