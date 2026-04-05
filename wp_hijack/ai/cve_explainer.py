"""AI CVE Explainer — plain-English explanation of a CVE for non-technical readers."""
from __future__ import annotations
from typing import Any

from .client import ask
from .exploit_prompts import build_cve_explain_prompt


async def explain_cve(finding: Any, ai_config: dict) -> str:
    """
    Returns a plain-English explanation of the CVE including:
    - What the vulnerability is
    - How it can be exploited
    - What data/access is at risk
    - Real-world analogy

    Suitable for inserting into executive reports.
    """
    prompt = build_cve_explain_prompt(finding)
    try:
        return await ask(
            prompt,
            system=(
                "You are a security consultant explaining vulnerabilities to a "
                "non-technical executive audience. Be concise (under 150 words), "
                "use everyday language, and include a real-world analogy."
            ),
            config=ai_config,
        )
    except Exception as exc:
        return (
            f"{finding.cve} — {finding.title}. "
            f"Affects {finding.component} v{finding.installed_version or 'unknown'}. "
            f"(AI explanation unavailable: {exc})"
        )
