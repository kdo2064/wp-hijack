"""AI WAF Bypass Suggestions — generates evasion techniques tailored to detected WAF."""

from __future__ import annotations

from typing import Any



from .client import ask

from .exploit_prompts import build_waf_bypass_prompt





async def generate_waf_bypass(

    finding: Any,

    waf_name: str,

    waf_confidence: int,

    target: str,

    ai_config: dict,

) -> str:

    """
    Given a confirmed vulnerability and detected WAF, generate targeted bypass
    techniques so the security team can verify the WAF is actually blocking the
    exploit and find gaps.

    Returns a markdown-formatted string with bypass strategies.
    """

    prompt = build_waf_bypass_prompt(finding, waf_name, waf_confidence, target)

    try:

        return await ask(

            prompt,

            system=(

                "You are a senior red-team engineer specialising in WAF evasion. "

                "Generate practical, specific WAF bypass techniques for an authorised "

                "penetration test. Structure the response in Markdown with sections for "

                "encoding tricks, header manipulation, payload fragmentation, and "

                "protocol-level bypasses. Include curl examples."

            ),

            config=ai_config,

        )

    except Exception as exc:

        return f"WAF bypass generation unavailable for {waf_name}: {exc}"

