"""AI False-Positive Filter — reviews detections and marks unlikely real vulns."""
from __future__ import annotations
import json
import re
from typing import Any

from .client import ask


_FP_SYSTEM = (
    "You are a senior application security engineer reviewing automated scanner "
    "output for false positives. For each finding, decide whether it is LIKELY_REAL, "
    "POSSIBLE_FP, or LIKELY_FP based on the evidence. Respond ONLY with a JSON array "
    "matching the input order, each element: "
    '{"cve": "...", "verdict": "LIKELY_REAL|POSSIBLE_FP|LIKELY_FP", "reason": "..."}'
)


async def filter_false_positives(
    findings: list[Any],   # PotentialFinding objects
    target: str,
    ai_config: dict,
) -> list[dict]:
    """
    Pass all findings to AI for false-positive review.

    Returns a list of dicts:
      [{"cve": str, "verdict": "LIKELY_REAL"|"POSSIBLE_FP"|"LIKELY_FP", "reason": str}, ...]
    Preserves input order; falls back to LIKELY_REAL on errors.
    """
    if not findings:
        return []

    items = [
        {
            "cve":       f.cve,
            "title":     f.title,
            "component": f.component,
            "version":   f.installed_version or "unknown",
            "severity":  f.severity,
            "cvss":      f.cvss,
            "desc":      f.description[:300],
        }
        for f in findings
    ]

    prompt = (
        f"Target: {target}\n\n"
        "Review these scanner findings for false positives. Consider: installed "
        "version vs affected range, component detection confidence, and whether "
        "the vulnerability type applies to WordPress environments.\n\n"
        f"Findings:\n{json.dumps(items, indent=2)}"
    )

    try:
        response = await ask(prompt, system=_FP_SYSTEM, config=ai_config)
        # strip markdown fence if present
        m = re.search(r"\[.*\]", response, re.S)
        raw = m.group(0) if m else response
        results = json.loads(raw)
        # validate & fill gaps
        out = []
        for idx, item in enumerate(items):
            matched = next((r for r in results if r.get("cve") == item["cve"]), None)
            if matched:
                out.append(matched)
            else:
                out.append({"cve": item["cve"], "verdict": "LIKELY_REAL", "reason": "No AI verdict"})
        return out
    except Exception as exc:
        # On any failure, mark all as LIKELY_REAL so nothing is silently dropped
        return [{"cve": f.cve, "verdict": "LIKELY_REAL", "reason": f"AI filter error: {exc}"} for f in findings]
