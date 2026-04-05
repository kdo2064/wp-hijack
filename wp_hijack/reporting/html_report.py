"""HTML report generator using Jinja2 template."""
from __future__ import annotations
import pathlib
import datetime
from typing import Any
from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = pathlib.Path(__file__).parent.parent / "templates"


def write_html_report(
    output_path: pathlib.Path,
    *,
    target: str,
    confirmed_findings: list[Any],
    users: list[Any],
    exposed_files: list[Any],
    cms_info: Any,
    waf: Any,
    elapsed: float,
    ai_summary: str | None = None,
    risk_score: dict | None = None,
) -> pathlib.Path:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")

    context = {
        "target":          target,
        "generated_at":    datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "elapsed":         f"{elapsed:.1f}",
        "cms": {
            "type":       cms_info.cms.value if cms_info else "Unknown",
            "version":    cms_info.version if cms_info else None,
            "confidence": cms_info.confidence if cms_info else 0,
        },
        "waf": {
            "detected": waf.detected if waf else False,
            "name":     waf.name if waf else None,
        },
        "vulnerabilities":  [cf.to_dict() for cf in confirmed_findings],
        "confirmed_count":  sum(1 for cf in confirmed_findings if cf.status.value == "CONFIRMED"),
        "potential_count":  sum(1 for cf in confirmed_findings if cf.status.value == "POTENTIAL"),
        "users":            [
            {"id": u.id, "login": u.login, "display_name": u.display_name, "source": u.source}
            for u in users
        ],
        "exposed_files":    [
            {"path": f.path, "status": f.status_code, "severity": f.severity}
            for f in exposed_files
        ],
        "ai_summary":   ai_summary,
        "risk_score":   risk_score,
    }

    html = template.render(**context)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
