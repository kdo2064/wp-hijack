"""AI executive summary generator."""

from __future__ import annotations

from typing import Any

from .client import ask





async def generate_summary(scan_results: dict, ai_config: dict) -> str:

    target    = scan_results.get("target", "unknown")

    confirmed = scan_results.get("confirmed_count", 0)

    potential = scan_results.get("potential_count", 0)

    criticals = scan_results.get("critical_count", 0)



    prompt = f"""Write a concise EXECUTIVE SUMMARY for a WordPress security scan report.

Target: {target}
Confirmed Vulnerabilities: {confirmed}
Potential Vulnerabilities: {potential}
Critical Severity: {criticals}

Write 3-4 paragraphs suitable for a non-technical executive audience covering:
1. Overall security posture (one sentence verdict)
2. Most critical findings summary
3. Business risk
4. Key next steps

Keep it professional, factual, and under 250 words."""



    try:

        return await ask(

            prompt,

            system="You are a senior cybersecurity consultant writing board-level security reports.",

            config=ai_config,

        )

    except Exception as exc:

        return (

            f"Security assessment of {target} identified {confirmed} confirmed vulnerabilities "

            f"and {potential} additional potential issues. Immediate remediation is recommended "

            f"for critical and high-severity findings. (AI summary unavailable: {exc})"

        )

