"""Rich display helpers — panels, tables, finding cards."""



from __future__ import annotations



from typing import Any



from rich.panel import Panel



from rich.table import Table



from rich.text import Text



from rich.columns import Columns



from rich.padding import Padding



from .theme import console, SEVERITY_COLORS, SEVERITY_BADGES, BRAND_GREEN, ACCENT_BLUE, BRAND_ORANGE











def _severity_text(sev: str) -> Text:



    badge, color = SEVERITY_BADGES.get(sev.upper(), (sev, "#FFFFFF"))



    return Text(badge, style=f"bold {color}")











def scan_header_panel(



    target: str,



    *,



    cms: str = "WordPress",



    version: str | None = None,



    waf: str | None = None,



    ip: str | None = None,



) -> None:



    """Print the scan target header panel."""



    lines: list[tuple[str, str]] = [



        ("Target", target),



        ("CMS", cms + (f"  {version}" if version else "")),



    ]



    if waf:



        lines.append(("WAF", waf))



    if ip:



        lines.append(("Server IP", ip))







    table = Table.grid(padding=(0, 2))



    table.add_column(style="scan.label", min_width=12)



    table.add_column(style="scan.value")



    for label, value in lines:



        table.add_row(label, value)







    console.print(



        Panel(



            table,



            title=f"[scan.target]⬡ SCAN TARGET[/]",



            border_style=ACCENT_BLUE,



            expand=False,



        )



    )



    console.print()











def findings_table(findings: list[dict[str, Any]]) -> None:



    """Print findings split into CONFIRMED and POTENTIAL tables."""



    if not findings:



        console.print("[vuln.clean]  No vulnerabilities found.[/]")



        return







    confirmed  = [f for f in findings if f.get("status") == "CONFIRMED"]



    potential  = [f for f in findings if f.get("status") != "CONFIRMED"]







    def _build_table(rows: list[dict[str, Any]], title: str, border: str) -> Table:



        tbl = Table(



            title=title,



            border_style=border,



            header_style=f"bold {border}",



            show_lines=True,



            expand=True,



        )



        tbl.add_column("#",          style="dim white", width=4, justify="right")



        tbl.add_column("Severity",   width=15)



        tbl.add_column("CVE",        style="finding.cve",    min_width=16)



        tbl.add_column("Component",  style="finding.plugin", min_width=20)



        tbl.add_column("Title",      style="finding.title",  min_width=30)



        tbl.add_column("CVSS",       style="finding.cvss",   width=6, justify="center")



        tbl.add_column("Status",     width=14)



        tbl.add_column("Evidence",   style="dim white",      min_width=30)







        for idx, f in enumerate(rows, 1):



            sev  = f.get("severity", "INFO")



            stat = f.get("status", "POTENTIAL")



            stat_style = "status.confirmed" if stat == "CONFIRMED" else "status.potential"



            evidence = (f.get("confirmation_evidence") or "")[:60]



            tbl.add_row(



                str(idx),



                _severity_text(sev),



                f.get("cve", "N/A"),



                f.get("component", "—"),



                f.get("title", "—"),



                str(f.get("cvss", "?")),



                Text(f"● {stat}", style=stat_style),



                evidence,



            )



        return tbl







    if confirmed:



        console.print(



            _build_table(



                confirmed,



                f"[scan.header]✔ CONFIRMED Vulnerabilities ({len(confirmed)})[/]",



                BRAND_GREEN,



            )



        )



        console.print()







    if potential:



        console.print(



            _build_table(



                potential,



                f"[scan.header]⚑ UNVERIFIED / POTENTIAL ({len(potential)})[/]",



                BRAND_ORANGE,



            )



        )



        console.print()







    if not confirmed and not potential:



        console.print("[vuln.clean]  No vulnerabilities found.[/]")



    console.print()











def finding_card(finding: dict[str, Any], exploit_code: dict[str, Any] | None = None) -> None:



    """Print a detailed card for one finding, including exploit if available."""



    sev = finding.get("severity", "INFO")



    color = SEVERITY_COLORS.get(sev, "#FFFFFF")







    header = Text()



    header.append(f"  {_severity_text(sev)}  ", style=f"bold {color}")



    header.append(finding.get("cve", ""), style="finding.cve")



    header.append("  —  ")



    header.append(finding.get("title", ""), style="finding.title")







    body = Table.grid(padding=(0, 2))



    body.add_column(style="scan.label", min_width=16)



    body.add_column()







    rows = [



        ("Component",   finding.get("component", "—")),



        ("CVSS Score",  str(finding.get("cvss", "?"))),



        ("Affected",    finding.get("affected_versions", "—")),



        ("Status",      finding.get("status", "POTENTIAL")),



        ("Description", finding.get("description", "")),



        ("Remediation", finding.get("remediation", "—")),



    ]



    if finding.get("references"):



        rows.append(("References", "  ".join(finding["references"][:3])))



                                                    

    conf_evidence = finding.get("confirmation_evidence")



    conf_url      = finding.get("confirmation_url")



    if conf_evidence:



        rows.append(("Verification", conf_evidence))



    if conf_url:



        rows.append(("Probed URL", conf_url))







    for label, value in rows:



        body.add_row(f"[scan.label]{label}[/]", value)









    if exploit_code:



        body.add_row("", "")



        _poc_label = "Static PoC" if exploit_code.get("is_static") else "AI-generated PoC"



        _poc_style = f"bold {BRAND_GREEN}" if exploit_code.get("is_static") else f"italic dim {BRAND_ORANGE}"



        body.add_row(



            "[stage.exploit]Exploit[/]",



            Text(f"✔ {_poc_label} (ready)", style=_poc_style),



        )



        if exploit_code.get("prerequisites"):



            body.add_row("[scan.label]Pre-reqs[/]", Text(exploit_code["prerequisites"], style="dim white"))



        if exploit_code.get("curl_command"):



            body.add_row("[scan.label]cURL PoC[/]", Text(exploit_code["curl_command"], style="#88FF88"))



        if exploit_code.get("manual_steps"):



            steps_text = "\n".join(



                f"  {i+1}. {s}" for i, s in enumerate(exploit_code["manual_steps"][:6])



            )



            body.add_row("[scan.label]Steps[/]", Text(steps_text, style="dim white"))



        if exploit_code.get("python_poc"):



            snippet = exploit_code["python_poc"][:400].rstrip()



            body.add_row(



                "[scan.label]Python PoC[/]",



                Text(snippet + "\n  ... (full PoC in JSON report)", style="dim #AAFFAA"),



            )



        if exploit_code.get("impact"):



            body.add_row("[scan.label]Impact[/]", Text(exploit_code["impact"], style=f"bold {BRAND_ORANGE}..."))







    console.print(



        Panel(



            Padding(body, (1, 2)),



            title=header,



            border_style=color,



            expand=True,



        )



    )











def scan_summary_panel(



    *,



    total_checks: int,



    confirmed: int,



    potential: int,



    elapsed: float,



    target: str,



) -> None:



    """Print the overall scan summary panel."""



    tbl = Table.grid(padding=(0, 3))



    tbl.add_column(style="scan.label")



    tbl.add_column(style="bold white")







    tbl.add_row("Target",            target)



    tbl.add_row("Total Checks",      str(total_checks))



    tbl.add_row("Confirmed Vulns",   f"[vuln.critical]{confirmed}[/]" if confirmed else "[vuln.clean]0[/]")



    tbl.add_row("Potential Vulns",   f"[vuln.medium]{potential}[/]" if potential else "[vuln.clean]0[/]")



    tbl.add_row("Elapsed",           f"{elapsed:.1f}s")







    console.print(



        Panel(



            tbl,



            title=f"[scan.done]✔ SCAN COMPLETE[/]",



            border_style=BRAND_GREEN,



            expand=False,



        )



    )



