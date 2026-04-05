"""Interactive AI chat — streaming Q&A about a completed scan."""

from __future__ import annotations

from typing import Any, AsyncIterator



from .client import ask, ask_stream



_CHAT_SYSTEM_TEMPLATE = """You are a cybersecurity expert assistant with full knowledge of the following WordPress security scan results.

Target: {target}
CMS Version: {version}
WAF: {waf}
Confirmed Vulnerabilities: {confirmed}
Potential Vulnerabilities: {potential}
Exposed Users: {users}
Sensitive Files Exposed: {exposed}

Top Findings:
{findings_block}

Answer user questions about this scan accurately and concisely. When asked for exploit code, provide it with a clear disclaimer that it is for authorised testing only. Use Markdown for structure."""





def _build_system_prompt(scan_results: dict) -> str:

    cms = scan_results.get("cms_info")

    waf = scan_results.get("waf")

    confirmed = scan_results.get("confirmed", [])

    users  = scan_results.get("users", [])

    exposed = scan_results.get("exposed", [])



    top_findings = []

    for cf in confirmed[:10]:

        f = cf.finding if hasattr(cf, "finding") else cf

        top_findings.append(f"  - [{f.severity}] {f.cve}: {f.title} ({f.component})")



    return _CHAT_SYSTEM_TEMPLATE.format(

        target   = scan_results.get("target", "unknown"),

        version  = cms.version if cms else "unknown",

        waf      = waf.name if waf and waf.detected else "None detected",

        confirmed= sum(1 for cf in confirmed if hasattr(cf, "status") and str(cf.status).endswith("CONFIRMED")),

        potential= len(confirmed),

        users    = len(users),

        exposed  = len(exposed),

        findings_block = "\n".join(top_findings) or "  (none)",

    )





class ScanChat:

    """
    Stateful chat session about a completed scan.

    Usage:
        chat = ScanChat(scan_results, ai_config)
        async for chunk in chat.ask_stream("Which CVE is most urgent?"):
            print(chunk, end="", flush=True)
    """



    def __init__(self, scan_results: dict, ai_config: dict) -> None:

        self._ai_cfg = ai_config

        self._system = _build_system_prompt(scan_results)

        self._history: list[dict[str, str]] = []



    async def ask_stream(self, question: str) -> AsyncIterator[str]:

        """Yield response tokens one chunk at a time (streaming)."""

        self._history.append({"role": "user", "content": question})

        full_response = ""

        try:

            async for chunk in ask_stream(

                question,

                system   = self._system,

                history  = self._history[:-1],

                config   = self._ai_cfg,

            ):

                full_response += chunk

                yield chunk

        except Exception as exc:

            err = f"\n[AI error: {exc}]"

            full_response += err

            yield err

        finally:

            self._history.append({"role": "assistant", "content": full_response})



    async def ask_once(self, question: str) -> str:

        """Non-streaming single-turn ask (for programmatic use)."""

        self._history.append({"role": "user", "content": question})

        try:

            response = await ask(

                question,

                system  = self._system,

                history = self._history[:-1],

                config  = self._ai_cfg,

            )

        except Exception as exc:

            response = f"[AI error: {exc}]"

        self._history.append({"role": "assistant", "content": response})

        return response



    def clear_history(self) -> None:

        self._history.clear()

