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
    """Print an overview table of all confirmed findings."""
    if not findings:
        console.print("[vuln.clean]  No vulnerabilities confirmed.[/]")
        return

    tbl = Table(
        title="[scan.header]Confirmed Findings[/]",
        border_style=BRAND_GREEN,
        header_style=f"bold {BRAND_GREEN}",
        show_lines=True,
        expand=True,
    )
    tbl.add_column("#",       style="dim white", width=4, justify="right")
    tbl.add_column("Severity",width=15)
    tbl.add_column("CVE",     style="finding.cve",    min_width=16)
    tbl.add_column("Component",style="finding.plugin", min_width=20)
    tbl.add_column("Title",   style="finding.title",  min_width=30)
    tbl.add_column("CVSS",    style="finding.cvss",   width=6, justify="center")
    tbl.add_column("Status",  width=14)

    for idx, f in enumerate(findings, 1):
        sev  = f.get("severity", "INFO")
        stat = f.get("status", "POTENTIAL")
        stat_style = "status.confirmed" if stat == "CONFIRMED" else "status.potential"
        tbl.add_row(
            str(idx),
            _severity_text(sev),
            f.get("cve", "N/A"),
            f.get("component", "—"),
            f.get("title", "—"),
            str(f.get("cvss", "?")),
            Text(f"● {stat}", style=stat_style),
        )

    console.print(tbl)
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

    for label, value in rows:
        body.add_row(f"[scan.label]{label}[/]", value)

    # Exploit section
    if exploit_code:
        body.add_row("", "")
        body.add_row(
            "[stage.exploit]Exploit PoC[/]",
            Text("AI-generated", style=f"italic dim {BRAND_ORANGE}"),
        )
        if exploit_code.get("curl_command"):
            body.add_row("[scan.label]cURL[/]", Text(exploit_code["curl_command"], style="dim #88FF88"))
        if exploit_code.get("impact"):
            body.add_row("[scan.label]Impact[/]", exploit_code["impact"])

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
