"""Async confirmation engine — runs SAFE/CAUTIOUS tests, returns ConfirmedFindings."""



from __future__ import annotations



import asyncio



from typing import Any







from .models import (



    PotentialFinding, ConfirmedFinding, ConfirmationResult,



    SafetyLevel, VulnStatus,



)



from .confirmation_tests import get_confirmation, generic_plugin_verify

from .static_exploits    import get_static_exploit











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



                                                                                  

        try:



            result = await generic_plugin_verify(http, base_url, finding)



            confirmed_finding.confirmation = result



            confirmed_finding.finding.status = result.status



                                            

            if result.confirmed:

                _poc = get_static_exploit(

                    finding.cve, base_url,

                    finding.component, finding.installed_version,

                )

                if _poc:

                    confirmed_finding.exploit = _poc



        except Exception as exc:



            confirmed_finding.confirmation = ConfirmationResult(



                confirmed=False,



                status=VulnStatus.POTENTIAL,



                evidence=f"Generic verification error: {exc}",



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



                                                                         

        if result.confirmed:

            _poc = get_static_exploit(

                finding.cve, base_url,

                finding.component, finding.installed_version,

            )

            if _poc:

                confirmed_finding.exploit = _poc



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





async def confirm_ai_poc(

    http,

    base_url: str,

    cf: ConfirmedFinding,

) -> ConfirmationResult:

    """
    Post-exploit-generation HTTP confirmation.

    After the AI has generated a PoC (using CVE research), re-run a
    targeted HTTP probe to verify the attack surface is STILL exposed and
    the generated PoC is viable — not just detected by version matching.

    Strategy
    ────────
    1. If a CVE-specific SAFE/CAUTIOUS test exists, run it again (fresh).
    2. Otherwise, run generic_plugin_verify with a stricter probe.
    3. Update cf.finding.status and cf.confirmation with the new result.

    Returns the new ConfirmationResult (also updates cf in-place).
    """

    test = get_confirmation(cf.finding.cve)



    result: ConfirmationResult | None = None



                                         

    if test and test["safety"] in (SafetyLevel.SAFE, SafetyLevel.CAUTIOUS):

        try:

            result = await test["run"](http, base_url, cf.finding)

        except Exception as exc:

            result = ConfirmationResult(

                confirmed=False,

                status=VulnStatus.POTENTIAL,

                evidence=f"CVE-specific re-check error: {exc}",

            )



                                                      

    if result is None:

        try:

            result = await generic_plugin_verify(http, base_url, cf.finding)

        except Exception as exc:

            result = ConfirmationResult(

                confirmed=False,

                status=VulnStatus.POTENTIAL,

                evidence=f"Generic re-check error: {exc}",

            )



                                                                             

    if result.confirmed:

        result.evidence = f"[PoC verified] {result.evidence}"

        result.status   = VulnStatus.CONFIRMED

    else:

        result.evidence = f"[PoC unverified] {result.evidence}"



                                          

    cf.confirmation        = result

    cf.finding.status      = result.status



    return result





async def confirm_ai_poc_batch(

    http,

    base_url: str,

    confirmed_findings: list[ConfirmedFinding],

) -> list[ConfirmationResult]:

    """
    Run confirm_ai_poc concurrently for every ConfirmedFinding that has a
    generated exploit but hasn't been actively re-verified yet.
    """

    targets = [

        cf for cf in confirmed_findings

        if cf.exploit is not None

    ]

    if not targets:

        return []



    tasks = [confirm_ai_poc(http, base_url, cf) for cf in targets]

    results = await asyncio.gather(*tasks, return_exceptions=True)



    out: list[ConfirmationResult] = []

    for cf, r in zip(targets, results):

        if isinstance(r, ConfirmationResult):

            out.append(r)

        else:

                                                    

            fallback = ConfirmationResult(

                confirmed=False,

                status=VulnStatus.POTENTIAL,

                evidence=f"[PoC re-check failed] {r}",

            )

            cf.confirmation   = fallback

            cf.finding.status = VulnStatus.POTENTIAL

            out.append(fallback)



    return out



