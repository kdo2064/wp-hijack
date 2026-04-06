"""
wp-Hijack main scan orchestrator.
9-phase async pipeline: Setup → WAF → CMS → Enumerate → Active Tests →
                        VulnMatch → Confirm → AI Exploit → Report
"""



from __future__ import annotations



import asyncio



import pathlib



import time



from typing import Any







from .config         import load_config, get_scanner_config, get_ai_config, get_exploit_config, get_confirmation_config, is_ai_enabled, is_pdf_enabled



from .http_client    import AsyncHTTPClient



from .recon          import run_recon, ReconInfo



from .cms            import detect_cms, CMSInfo



from .waf            import detect_waf, WAFResult



from .enumerators    import enumerate_plugins, enumerate_themes, enumerate_users



from .active_tests   import test_xmlrpc, test_rest_api, test_login_security, check_file_exposure, probe_injections



from .vulndb         import init_db, load_bundled, query_by_component, is_version_affected, fetch_bulk



from .pipeline       import PotentialFinding, VulnStatus, ExploitCode, confirm_batch, confirm_ai_poc_batch



from .ai             import (ExploitGenerator, score_risk, generate_summary,



                              generate_attack_chain, explain_cve, generate_waf_bypass,



                              filter_false_positives)



from .ui.theme       import console



from .ui.status      import PhaseSpinner, phase_header



from .ui.progress    import ScanProgress











class Scanner:



    def __init__(self, config_path: str | pathlib.Path | None = None) -> None:



        self.cfg = load_config(config_path)



        self._target: str = ""



        self._results: dict[str, Any] = {}







    async def scan(self, target: str) -> dict[str, Any]:



        self._target = target.rstrip("/")



        t_start = time.monotonic()



        results: dict[str, Any] = {



            "target":       self._target,



            "recon":        None,



            "cms_info":     None,



            "waf":          None,



            "plugins":      [],



            "themes":       [],



            "users":        [],



            "xmlrpc":       None,



            "rest_api":     None,



            "login_sec":    None,



            "exposed":      [],



            "injections":   None,



            "findings":     [],



            "confirmed":    [],



            "ai_summary":   None,



            "risk_score":   None,



            "attack_chain": None,



            "elapsed":      0.0,



        }







        async with AsyncHTTPClient(self.cfg) as http:









            phase_header("Phase 0/10  ·  Recon")



            with console.status("[scan.phase]Gathering target intelligence...[/]", spinner="dots"):



                recon_info = await run_recon(http, self._target)



            results["recon"] = recon_info



            _ip_str = f"[bold white]{recon_info.ip}[/]" if recon_info.ip else (



                f"[dim]unknown ({recon_info.ip_error})[/]" if recon_info.ip_error else "[dim]unknown[/]"



            )



            _loc_parts = [p for p in [recon_info.city, recon_info.region, recon_info.country] if p]



            _loc_str = ", ".join(_loc_parts) if _loc_parts else ""



            _org_str = f" · {recon_info.org}" if recon_info.org else ""



            console.print(f"  [scan.done]✔[/]  IP: {_ip_str}" + (f"  ·  {_loc_str}{_org_str}" if _loc_str else ""))



            if recon_info.page_title:



                console.print(f"  [scan.done] [/]  Title: [italic white]{recon_info.page_title}[/]")



            if recon_info.server:



                console.print(f"  [scan.done] [/]  Server: [dim white]{recon_info.server}[/]" + (f"  ·  {recon_info.powered_by}" if recon_info.powered_by else ""))



            if recon_info.ssl_expiry:



                ssl_color = "green" if recon_info.ssl_valid else "red"



                console.print(f"  [scan.done] [/]  SSL: [{ssl_color}]{recon_info.ssl_issuer or 'Unknown CA'}[/{ssl_color}]  expires {recon_info.ssl_expiry} ({recon_info.ssl_days_left}d)")









            phase_header("Phase 2/10  ·  WAF Detection")



            with PhaseSpinner("Detecting WAF") as sp:



                waf = await detect_waf(http, self._target)



                results["waf"] = waf



                done = f"WAF: {waf.name} (confidence {waf.confidence}%)" if waf.detected else "No WAF detected"







            if waf.detected:



                console.print(f"  [scan.warn]⚠ WAF detected:[/] [bold white]{waf.name}[/]  (passthrough testing continues)")









            phase_header("Phase 3/10  ·  CMS Detection")



            with console.status("[scan.phase]Detecting CMS...[/]", spinner="dots"):



                cms = await detect_cms(http, self._target)



                results["cms_info"] = cms







            console.print(f"  [scan.done]✔[/]  CMS: [bold white]{cms.cms.value}[/]  version: [bold white]{cms.version or 'unknown'}[/]  confidence: {cms.confidence}%")









            home_html = results["recon"].home_html if results["recon"] else ""



            if not home_html:



                try:



                    r = await http.get(self._target)



                    home_html = r.text or ""



                except Exception:



                    pass









            phase_header("Phase 4/10  ·  Enumeration")



            with console.status("[scan.phase]Enumerating plugins, themes, users...[/]", spinner="dots"):



                plugins, themes, users = await asyncio.gather(



                    enumerate_plugins(http, self._target, home_html),



                    enumerate_themes(http, self._target, home_html),



                    enumerate_users(http, self._target, home_html),



                )



            results["plugins"] = plugins



            results["themes"]  = themes



            results["users"]   = users



            console.print(f"  [scan.done]✔[/]  Found [bold white]{len(plugins)}[/] plugins, [bold white]{len(themes)}[/] themes, [bold white]{len(users)}[/] users")









            phase_header("Phase 5/10  ·  Active Tests")



            with console.status("[scan.phase]Running active checks...[/]", spinner="dots"):



                xmlrpc, rest_api, login_sec, exposed, injections = await asyncio.gather(



                    test_xmlrpc(http, self._target),



                    test_rest_api(http, self._target),



                    test_login_security(http, self._target),



                    check_file_exposure(http, self._target),



                    probe_injections(http, self._target),



                )



            results["xmlrpc"]     = xmlrpc



            results["rest_api"]   = rest_api



            results["login_sec"]  = login_sec



            results["exposed"]    = exposed



            results["injections"] = injections



            console.print(



                f"  [scan.done]✔[/]  XML-RPC: {'enabled' if xmlrpc.enabled else 'disabled'} | "



                f"REST exposed: {'yes' if rest_api.users_exposed else 'no'} | "



                f"Sensitive files: {len(exposed)}"



            )









            phase_header("Phase 6/10  ·  VulnDB Matching")



            _db_path_cfg = self.cfg.get("vulndb", {}).get("db_path", "")



            db_path = pathlib.Path(_db_path_cfg) if _db_path_cfg else pathlib.Path(__file__).parent / "vulndb" / "wp_hijack.db"



            await init_db(db_path)



            await load_bundled(db_path)









            import json as _json



            potential_findings: list[PotentialFinding] = []





            _seen_finding_keys: set[str] = set()







            def _add_finding(pf: PotentialFinding) -> None:



                key = f"{pf.cve}::{pf.component}"



                if key not in _seen_finding_keys:



                    _seen_finding_keys.add(key)



                    potential_findings.append(pf)







            components_to_check: list[tuple[str, str | None, str]] = []









            if cms.version:



                components_to_check.append(("wordpress", cms.version, "core"))





            for p in plugins:



                components_to_check.append((p.slug, p.version, "plugin"))





            for t in themes:



                if t.version:



                    components_to_check.append((t.slug, t.version, "theme"))



                else:



                    components_to_check.append((t.slug, None, "theme"))









            with console.status("[scan.phase]Matching components against local vuln DB...[/]", spinner="dots"):



                for slug, version, comp_type in components_to_check:



                    db_vulns = await query_by_component(slug, db_path)



                    for vuln in db_vulns:



                        affected = _json.loads(vuln["affected_versions"]) if isinstance(vuln["affected_versions"], str) else vuln["affected_versions"]



                        _refs_raw = vuln.get("vuln_references") or vuln.get("references") or "[]"



                        refs     = _json.loads(_refs_raw) if isinstance(_refs_raw, str) else _refs_raw



                        hit = is_version_affected(version, affected) if version else False



                        if hit:



                            pf = PotentialFinding(



                                cve=vuln["cve"],



                                title=vuln["title"],



                                description=vuln["description"],



                                severity=vuln["severity"],



                                cvss=float(vuln["cvss"] or 5.0),



                                component=slug,



                                component_type=comp_type,



                                installed_version=version,



                                affected_versions=affected,



                                fixed_version=vuln["fixed_version"],



                                references=refs,



                                remediation=vuln["remediation"] or "",



                                status=VulnStatus.DETECTED,



                            )



                            _add_finding(pf)







            local_count = len(potential_findings)



            console.print(f"  [scan.done]✔[/]  Local DB: [bold white]{local_count}[/] matches")









            _wpvuln_enabled = self.cfg.get("vulndb", {}).get("wpvulnerability_api", True)



            if _wpvuln_enabled:



                with console.status("[scan.phase]Querying WPVulnerability.net live API...[/]", spinner="dots"):



                    api_core    = cms.version if cms.version else None



                    api_plugins = [(p.slug, p.version) for p in plugins]



                    api_themes  = [(t.slug, t.version) for t in themes]



                    try:



                        live_findings = await fetch_bulk(



                            core_version=api_core,



                            plugins=api_plugins,



                            themes=api_themes,



                        )



                        for pf in live_findings:



                            _add_finding(pf)



                        live_count = len(potential_findings) - local_count



                        console.print(



                            f"  [scan.done]✔[/]  WPVulnerability.net: [bold white]{live_count}[/] new findings"



                            f"  ([dim]{len(live_findings)} total from API[/])"



                        )



                    except Exception as _exc:



                        console.print(f"  [scan.warn]⚠ WPVulnerability.net API unavailable: {_exc}[/]")



            else:



                console.print("  [dim]WPVulnerability.net API disabled in config[/]")







            console.print(f"  [scan.done]✔[/]  Total potential vulnerabilities: [bold white]{len(potential_findings)}[/]")



            results["findings"] = potential_findings









            phase_header("Phase 8/10  ·  Active Confirmation")



            conf_cfg = get_confirmation_config(self.cfg)



            allow_cautious = conf_cfg.get("allow_cautious_tests", False)







            if conf_cfg.get("run_confirmations", True) and potential_findings:



                console.print(



                    f"  [scan.phase]Verifying [bold white]{len(potential_findings)}[/] potential"



                    f" vulnerabilities via live HTTP probes...[/]"



                )



                with console.status(



                    f"[scan.phase]Running verification checks ({len(potential_findings)} vulns)...[/]",



                    spinner="dots",



                ):



                    confirmed = await confirm_batch(



                        http, self._target, potential_findings,



                        allow_cautious=allow_cautious,



                    )



            else:



                from .pipeline.confirmer import confirm_batch as _cb



                from .pipeline.models import ConfirmedFinding, ConfirmationResult



                confirmed = [



                    ConfirmedFinding(



                        finding=f,



                        confirmation=ConfirmationResult(False, VulnStatus.POTENTIAL, "Confirmation disabled"),



                    )



                    for f in potential_findings



                ]







            c_count = sum(1 for cf in confirmed if cf.status == VulnStatus.CONFIRMED)



            p_count = sum(1 for cf in confirmed if cf.status == VulnStatus.POTENTIAL)



            poc_count = sum(1 for cf in confirmed if cf.exploit is not None)



            console.print(



                f"  [scan.done]✔[/]  Verification complete: "



                f"[bold #00FF41]{c_count} CONFIRMED[/]  ·  "



                f"[bold yellow]{p_count} unverified (POTENTIAL)[/]"



                f"  out of [white]{len(confirmed)}[/] total"



            )



            if poc_count:



                console.print(



                    f"  [scan.done]✔[/]  Static PoC exploits ready: "



                    f"[bold #FF6B35]{poc_count}[/] confirmed vulnerabilities have prebuilt PoC + cURL"



                )



            results["confirmed"] = confirmed









            if is_ai_enabled(self.cfg):



                phase_header("Phase 9/10  ·  AI Agent (8 modules)")



                exploit_cfg = get_exploit_config(self.cfg)



                ai_cfg      = get_ai_config(self.cfg)



                auto_sev    = set(exploit_cfg.get("auto_generate_severity", ["CRITICAL", "HIGH"]))



                gen         = ExploitGenerator(ai_cfg)









                all_findings_flat = [cf.finding for cf in confirmed]



                if all_findings_flat:



                    with console.status("[scan.phase]AI: Filtering false positives...[/]", spinner="dots"):



                        try:



                            fp_results = await filter_false_positives(all_findings_flat, self._target, ai_cfg)



                            fp_map = {r["cve"]: r for r in fp_results}



                            fp_flagged = 0



                            for cf in confirmed:



                                verdict = fp_map.get(cf.finding.cve, {})



                                cf.finding._fp_verdict = verdict



                                if verdict.get("verdict") == "LIKELY_FP":



                                    fp_flagged += 1



                            console.print(



                                f"  [scan.done]✔[/]  FP filter: [bold white]{fp_flagged}[/] likely false positives flagged"



                            )



                        except Exception as exc:



                            console.print(f"  [scan.warn]⚠ False-positive filter failed: {exc}[/]")









                targets_for_exploit = [



                    cf for cf in confirmed



                    if cf.finding.severity in auto_sev



                    and exploit_cfg.get("auto_generate", True)



                    and cf.exploit is None                                        



                ]



                _static_poc_count = sum(1 for cf in confirmed if cf.exploit is not None)



                if _static_poc_count:



                    console.print(



                        f"  [scan.done]✔[/]  Skipping AI exploit gen for "



                        f"[bold #FF6B35]{_static_poc_count}[/] finding(s) — static PoC already attached"



                    )







                if targets_for_exploit:



                    with console.status(

                        f"[scan.phase]AI: Fetching CVE docs + generating research-grounded PoC"

                        f" for {len(targets_for_exploit)} finding(s)...[/]",

                        spinner="dots",

                    ):

                        for cf in targets_for_exploit:

                            try:

                                                                                       

                                                                             

                                exploit = await gen.generate_with_research(

                                    cf.finding, cf.confirmation, self._target

                                )

                                cf.exploit = exploit

                            except Exception as exc:

                                console.print(f"  [scan.warn]⚠ Exploit generation failed for {cf.finding.cve}: {exc}[/]")



                    console.print(f"  [scan.done]✔[/]  Research-grounded PoCs generated for [bold white]{len(targets_for_exploit)}[/] finding(s)")



                                                                                     

                                                                                

                                                                               

                                                                            

                    with console.status(

                        "[scan.phase]AI: Verifying PoC exploitability via live HTTP probes...[/]",

                        spinner="dots",

                    ):

                        try:

                            poc_results = await confirm_ai_poc_batch(

                                http, self._target, confirmed

                            )

                            poc_verified  = sum(1 for r in poc_results if r.confirmed)

                            poc_potential = sum(1 for r in poc_results if not r.confirmed)

                            console.print(

                                f"  [scan.done]✔[/]  PoC HTTP re-verification: "

                                f"[bold #00FF41]{poc_verified} verified[/]  ·  "

                                f"[bold yellow]{poc_potential} unverified[/]"

                            )

                        except Exception as exc:

                            console.print(f"  [scan.warn]⚠ PoC verification pass failed: {exc}[/]")









                explain_targets = [cf for cf in confirmed if cf.finding.severity in auto_sev]



                if explain_targets:



                    with console.status(f"[scan.phase]AI: Explaining {len(explain_targets)} CVE(s)...[/]", spinner="dots"):



                        for cf in explain_targets:



                            try:



                                explanation = await explain_cve(cf.finding, ai_cfg)



                                cf.finding._cve_explain = explanation



                            except Exception as exc:



                                console.print(f"  [scan.warn]⚠ CVE explain failed for {cf.finding.cve}: {exc}[/]")



                    console.print(f"  [scan.done]✔[/]  CVE explanations added for [bold white]{len(explain_targets)}[/] finding(s)")









                if waf.detected and targets_for_exploit:



                    with console.status(f"[scan.phase]AI: Generating WAF bypass for {waf.name}...[/]", spinner="dots"):



                        try:





                            top_cf = targets_for_exploit[0]



                            bypass_text = await generate_waf_bypass(



                                top_cf.finding, waf.name, waf.confidence, self._target, ai_cfg



                            )



                            top_cf.finding._waf_bypass = bypass_text



                            console.print(f"  [scan.done]✔[/]  WAF bypass techniques generated for [bold white]{waf.name}[/]")



                        except Exception as exc:



                            console.print(f"  [scan.warn]⚠ WAF bypass generation failed: {exc}[/]")









                if all_findings_flat:



                    try:



                        with console.status("[scan.phase]AI: Generating executive summary & risk score...[/]", spinner="dots"):



                            scan_stat = {



                                "target":          self._target,



                                "confirmed_count": c_count,



                                "potential_count": len(confirmed) - c_count,



                                "critical_count":  sum(1 for cf in confirmed if cf.finding.severity == "CRITICAL"),



                            }



                            results["ai_summary"] = await generate_summary(scan_stat, ai_cfg)



                            results["risk_score"] = await score_risk(



                                [cf.finding for cf in confirmed], self._target, ai_cfg



                            )



                        console.print(f"  [scan.done]✔[/]  Executive summary & risk score complete")



                    except Exception as exc:



                        console.print(f"  [scan.warn]⚠ AI summary failed: {exc}[/]")



                else:





                    try:



                        with console.status("[scan.phase]AI: Generating clean-site summary...[/]", spinner="dots"):



                            clean_stat = {



                                "target":          self._target,



                                "confirmed_count": 0,



                                "potential_count": 0,



                                "critical_count":  0,



                            }



                            results["ai_summary"] = await generate_summary(clean_stat, ai_cfg)



                        console.print(f"  [scan.done]✔[/]  Clean-site AI summary generated")



                    except Exception as exc:



                        _exc_s = str(exc)



                        if "connection" in _exc_s.lower() or "refused" in _exc_s.lower():



                            _ollama_url = ai_cfg.get("base_url", "http://localhost:11434")



                            console.print(f"  [scan.warn]⚠ Ollama unreachable at {_ollama_url} — run [bold]ollama serve[/][/]")



                        else:



                            console.print(f"  [scan.warn]⚠ AI clean-site summary failed: {exc}[/]")









                if all_findings_flat:



                    with console.status("[scan.phase]AI: Building attack chain...[/]", spinner="dots"):



                        try:



                            attack_chain = await generate_attack_chain(



                                all_findings_flat[:15],



                                self._target,



                                waf.name if waf.detected else None,



                                ai_cfg,



                            )



                            results["attack_chain"] = attack_chain



                            console.print(f"  [scan.done]✔[/]  Attack chain analysis complete")



                        except Exception as exc:



                            console.print(f"  [scan.warn]⚠ Attack chain generation failed: {exc}[/]")







            else:



                phase_header("Phase 9/10  ·  AI (disabled)")



                console.print("  [dim]AI disabled — skipping all AI modules[/]")









            results["elapsed"] = time.monotonic() - t_start







        return results



