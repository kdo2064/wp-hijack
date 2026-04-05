"""Async confirmation engine — runs SAFE/CAUTIOUS tests, returns ConfirmedFindings."""
from __future__ import annotations
import asyncio
from typing import Any

from .models import (
    PotentialFinding, ConfirmedFinding, ConfirmationResult,
    SafetyLevel, VulnStatus,
)
from .confirmation_tests import get_confirmation


async def confirm_finding(
    http,
    base_url: str,
    finding: PotentialFinding,
    *,
    allow_cautious: bool = False,
) -> ConfirmedFinding:
    """
    Run the active confirmation test for a single finding (if registered).
    Returns ConfirmedFinding with populated confirmation result.
    """
    test = get_confirmation(finding.cve)
    confirmed_finding = ConfirmedFinding(finding=finding)

    if test is None:
        # No test registered — stay DETECTED/POTENTIAL
        confirmed_finding.confirmation = ConfirmationResult(
            confirmed=False,
            status=VulnStatus.POTENTIAL,
            evidence="No active confirmation test registered for this CVE",
        )
        return confirmed_finding

    safety: SafetyLevel = test["safety"]
    if safety == SafetyLevel.UNSAFE:
        confirmed_finding.confirmation = ConfirmationResult(
            confirmed=False,
            status=VulnStatus.POTENTIAL,
            evidence="Test skipped (UNSAFE — never auto-executed)",
        )
        return confirmed_finding

    if safety == SafetyLevel.CAUTIOUS and not allow_cautious:
        confirmed_finding.confirmation = ConfirmationResult(
            confirmed=False,
            status=VulnStatus.POTENTIAL,
            evidence="Test skipped (CAUTIOUS mode disabled in config)",
        )
        return confirmed_finding

    try:
        result: ConfirmationResult = await test["run"](http, base_url, finding)
        confirmed_finding.confirmation = result
        confirmed_finding.finding.status = result.status
    except Exception as exc:
        confirmed_finding.confirmation = ConfirmationResult(
            confirmed=False,
            status=VulnStatus.POTENTIAL,
            evidence=f"Confirmation test error: {exc}",
        )

    return confirmed_finding


async def confirm_batch(
    http,
    base_url: str,
    findings: list[PotentialFinding],
    *,
    allow_cautious: bool = False,
) -> list[ConfirmedFinding]:
    """Confirm all findings concurrently."""
    tasks = [
        confirm_finding(http, base_url, f, allow_cautious=allow_cautious)
        for f in findings
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[ConfirmedFinding] = []
    for r, f in zip(results, findings):
        if isinstance(r, ConfirmedFinding):
            out.append(r)
        else:
            # Task raised an exception — wrap with POTENTIAL
            cf = ConfirmedFinding(
                finding=f,
                confirmation=ConfirmationResult(
                    confirmed=False,
                    status=VulnStatus.POTENTIAL,
                    evidence=f"Confirmation error: {r}",
                ),
            )
            out.append(cf)
    return out
