"""Rich terminal report printer."""



from __future__ import annotations



from typing import Any



from rich.rule import Rule



from ..ui.theme import console, BRAND_GREEN, ACCENT_BLUE, BRAND_ORANGE



from ..ui.display import findings_table, finding_card, scan_summary_panel, scan_header_panel











def print_scan_start(target: str, cms_info: Any, waf: Any) -> None:



    waf_name = waf.name if waf and waf.detected else "None detected"



    scan_header_panel(



        target,



        cms=cms_info.cms.value if cms_info else "Unknown",



        version=cms_info.version if cms_info else None,



        waf=waf_name,



    )











def print_findings_summary(confirmed_findings: list[Any]) -> None:



    dicts = [cf.to_dict() for cf in confirmed_findings]



    findings_table(dicts)











def print_finding_detail(cf: Any) -> None:



    finding_dict = cf.to_dict()



    exploit_dict = None



    if cf.exploit:



        exploit_dict = {



            "curl_command": cf.exploit.curl_command,



            "impact": cf.exploit.impact,



        }



    finding_card(finding_dict, exploit_dict)











def print_summary(*, target: str, total_checks: int, confirmed: int, potential: int, elapsed: float) -> None:



    scan_summary_panel(



        target=target,



        total_checks=total_checks,



        confirmed=confirmed,



        potential=potential,



        elapsed=elapsed,



    )











def print_users(users: list[Any]) -> None:



    if not users:



        return



    from rich.table import Table



    tbl = Table(title="[scan.header]Enumerated Users[/]", border_style=ACCENT_BLUE, header_style=f"bold {ACCENT_BLUE}")



    tbl.add_column("ID",      style="dim white", width=5)



    tbl.add_column("Login",   style="bold white")



    tbl.add_column("Display", style="white")



    tbl.add_column("Source",  style="dim white")



    for u in users:



        tbl.add_row(str(u.id or "?"), u.login or "?", u.display_name or "", u.source)



    console.print(tbl)











def print_exposed_files(files: list[Any]) -> None:



    if not files:



        return



    from rich.table import Table



    tbl = Table(title="[scan.header]Exposed Sensitive Files[/]", border_style=BRAND_ORANGE, header_style=f"bold {BRAND_ORANGE}")



    tbl.add_column("Path",     style="bold white", min_width=40)



    tbl.add_column("Status",   width=8, justify="center")



    tbl.add_column("Size",     width=10)



    tbl.add_column("Severity", width=10)



    for f in files:



        tbl.add_row(f.path, str(f.status_code), str(f.size_bytes), f.severity)



    console.print(tbl)



