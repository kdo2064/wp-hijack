"""Markdown report writer — full wp-Hijack scan report in Markdown format."""
from __future__ import annotations
import datetime
import pathlib
from typing import Any


def write_markdown_report(
    output_path: pathlib.Path,
    *,
    target: str,
    scan_meta: dict[str, Any],
    confirmed_findings: list[Any],
    users: list[Any],
    exposed_files: list[Any],
    xmlrpc: Any,
    rest_api: Any,
    login_sec: Any,
    waf: Any,
    cms_info: Any,
    ai_summary: str | None = None,
    risk_score: dict | None = None,
    attack_chain: str | None = None,
    elapsed: float = 0.0,
) -> pathlib.Path:
    """Write a complete Markdown-formatted security report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []

    def h(level: int, text: str) -> None:
        lines.append(f"{'#' * level} {text}\n")

    def line(text: str = "") -> None:
        lines.append(text + "\n")

    def hr() -> None:
        lines.append("---\n")

    # ── Title ─────────────────────────────────────────────────────────────────
    h(1, "wp-Hijack Security Assessment Report")
    line(f"> Generated: **{now}**  |  Tool: **wp-Hijack v1.0.0**  |  Author: KDO || Xpert Exploit")
    hr()

    # ── Target Overview ───────────────────────────────────────────────────────
    h(2, "Target Overview")
    cms_ver  = cms_info.version if cms_info else "unknown"
    cms_type = cms_info.cms.value if cms_info else "unknown"
    waf_str  = (f"{waf.name} (confidence: {waf.confidence}%)" if waf and waf.detected else "None detected")
    wp_ver   = scan_meta.get("wp_version") or cms_ver

    line(f"| Field | Value |")
    line(f"|-------|-------|")
    line(f"| **Target URL** | `{target}` |")
    line(f"| **CMS** | {cms_type} {wp_ver} |")
    line(f"| **WAF** | {waf_str} |")
    line(f"| **Scan Duration** | {elapsed:.1f}s |")
    line(f"| **Findings** | {len(confirmed_findings)} total |")
    line()

    # ── Risk Score ────────────────────────────────────────────────────────────
    if risk_score:
        h(2, "Risk Assessment")
        score = risk_score.get("score", risk_score.get("OVERALL RISK SCORE", "N/A"))
        line(f"**Overall Risk Score:** `{score} / 10`\n")
        for k, v in risk_score.items():
            if k != "score":
                line(f"- **{k.replace('_', ' ').title()}:** {v}")
        line()

    # ── AI Executive Summary ──────────────────────────────────────────────────
    if ai_summary:
        h(2, "Executive Summary")
        line(ai_summary)
        line()

    # ── AI Attack Chain ───────────────────────────────────────────────────────
    if attack_chain:
        h(2, "AI-Generated Attack Chain")
        line(attack_chain)
        line()

    # ── Vulnerability Findings ────────────────────────────────────────────────
    h(2, "Vulnerability Findings")

    if not confirmed_findings:
        line("> ✅ No vulnerabilities detected.")
    else:
        _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            confirmed_findings,
            key=lambda cf: _sev_order.get((cf.finding.severity if hasattr(cf, "finding") else cf.severity).upper(), 5),
        )
        for idx, cf in enumerate(sorted_findings, 1):
            f = cf.finding if hasattr(cf, "finding") else cf
            status = cf.status.value if hasattr(cf, "status") else "POTENTIAL"
            exploit = getattr(cf, "exploit", None)
            fp_verdict = getattr(f, "_fp_verdict", None)
            cve_explain = getattr(f, "_cve_explain", None)
            waf_bypass  = getattr(f, "_waf_bypass", None)

            sev_badge = {
                "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"
            }.get(f.severity.upper(), "⚪")

            h(3, f"{idx}. {sev_badge} [{f.severity}] {f.cve} — {f.title}")
            line(f"| Field | Value |")
            line(f"|-------|-------|")
            line(f"| **Status** | `{status}` |")
            line(f"| **Component** | {f.component} |")
            line(f"| **Version** | {f.installed_version or 'unknown'} |")
            line(f"| **Fixed In** | {f.fixed_version or 'See advisory'} |")
            line(f"| **CVSS** | {f.cvss} |")
            if fp_verdict:
                line(f"| **FP Assessment** | {fp_verdict.get('verdict', '')} — {fp_verdict.get('reason', '')} |")
            line()
            line(f"**Description:** {f.description}")
            line()

            if cve_explain:
                line(f"**Plain-English Explanation:**")
                line(f"> {cve_explain}")
                line()

            if f.remediation:
                line(f"**Remediation:** {f.remediation}")
                line()

            if waf_bypass:
                line("<details>")
                line("<summary>WAF Bypass Techniques</summary>")
                line()
                line(waf_bypass)
                line("</details>")
                line()

            if exploit:
                if exploit.python_poc:
                    line("**Python PoC:**")
                    line("```python")
                    line(exploit.python_poc)
                    line("```")
                    line()
                if exploit.curl_command:
                    line("**Curl Command:**")
                    line("```bash")
                    line(exploit.curl_command)
                    line("```")
                    line()
                if exploit.manual_steps:
                    line("**Manual Steps:**")
                    for step in exploit.manual_steps:
                        line(f"1. {step}")
                    line()

            if f.references:
                refs = f.references if isinstance(f.references, list) else [f.references]
                line("**References:** " + " · ".join(f"[link]({r})" for r in refs[:5]))
                line()

            hr()

    # ── Attack Surface ────────────────────────────────────────────────────────
    h(2, "Attack Surface")

    # XML-RPC
    h(3, "XML-RPC")
    if xmlrpc:
        line(f"- **Enabled:** {'Yes ⚠️' if xmlrpc.enabled else 'No ✅'}")
        if xmlrpc.enabled:
            line(f"- **Multicall Allowed:** {'Yes ⚠️' if xmlrpc.multicall_allowed else 'No'}")
            line(f"- **Pingback Enabled:** {'Yes ⚠️' if xmlrpc.pingback_enabled else 'No'}")
            if xmlrpc.methods:
                line(f"- **Methods ({len(xmlrpc.methods)}):** " + ", ".join(f"`{m}`" for m in xmlrpc.methods[:10]))
    line()

    # REST API
    h(3, "REST API")
    if rest_api:
        line(f"- **Reachable:** {'Yes' if rest_api.reachable else 'No'}")
        line(f"- **Users Exposed:** {'Yes ⚠️' if rest_api.users_exposed else 'No ✅'}")
        line(f"- **WooCommerce Endpoints:** {'Yes ⚠️' if rest_api.woocommerce_exposed else 'No'}")
        if rest_api.namespaces:
            line(f"- **Namespaces:** " + ", ".join(f"`{n}`" for n in rest_api.namespaces[:8]))
    line()

    # Login Security
    h(3, "Login Security")
    if login_sec:
        line(f"- **Login Page Accessible:** {'Yes' if login_sec.login_accessible else 'No'}")
        line(f"- **Username Enumeration:** {'Yes ⚠️' if login_sec.username_oracle else 'No ✅'}")
        line(f"- **No Rate Limiting:** {'Yes ⚠️' if login_sec.no_rate_limit else 'No ✅'}")
        line(f"- **Open Registration:** {'Yes ⚠️' if login_sec.open_registration else 'No'}")
    line()

    # Sensitive Files
    h(3, "Exposed Sensitive Files")
    if exposed_files:
        line("| Path | Status | Severity |")
        line("|------|--------|----------|")
        for ef in exposed_files:
            line(f"| `{ef.path}` | {ef.status_code} | {ef.severity} |")
    else:
        line("> ✅ No sensitive files exposed.")
    line()

    # ── Users ─────────────────────────────────────────────────────────────────
    h(2, "Enumerated Users")
    if users:
        line("| ID | Login | Display Name | Source |")
        line("|----|-------|--------------|--------|")
        for u in users:
            line(f"| {u.id} | `{u.login}` | {u.display_name or ''} | {u.source} |")
    else:
        line("> No users enumerated.")
    line()

    # ── Footer ────────────────────────────────────────────────────────────────
    hr()
    line("> **Disclaimer:** This report was generated for authorised security testing purposes only.")
    line(f"> wp-Hijack — github.com/kdo2064/wp-Hijack")

    output_path.write_text("".join(lines), encoding="utf-8")
    return output_path
