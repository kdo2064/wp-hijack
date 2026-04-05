"""AI Attack Chain Generator — builds a realistic multi-step attack narrative."""

from __future__ import annotations

from typing import Any



from .client import ask

from .exploit_prompts import build_attack_chain_prompt





async def generate_attack_chain(

    findings: list[Any],

    target: str,

    waf_name: str | None,

    ai_config: dict,

) -> str:

    """
    Given a list of findings for a target, ask AI to construct the most
    realistic end-to-end attack chain an adversary would follow.

    Returns a markdown-formatted narrative string.
    """

    if not findings:

        return "No findings available to build an attack chain."



    prompt = build_attack_chain_prompt(findings, target, waf_name)

    try:

        return await ask(

            prompt,

            system=(

                "You are a senior penetration tester writing an authorised security "

                "assessment report. Build a realistic, step-by-step attack chain "

                "that chains the provided findings from initial foothold to full "

                "site compromise. Use Markdown with numbered steps and sub-steps."

            ),

            config=ai_config,

        )

    except Exception as exc:

        return f"Attack chain generation unavailable: {exc}"

