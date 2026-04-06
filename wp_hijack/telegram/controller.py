"""
BotController — long-poll Telegram bot that lets authorised users
control wp-Hijack scans from Telegram.

Supported commands:
    /start          — welcome + quick help
    /help           — full command list
    /scan <url>     — kick off a new scan (background)
    /agent <url>    — kick off autonomous agent mode
    /status         — current scan status / last results summary
    /findings       — list confirmed findings from last scan
    /stop           — attempt to abort current scan
    /report         — resend the last generated report PDF
    /config         — show current config (safe fields only)

Usage::

    ctrl = BotController(tg_cfg=cfg["telegram"], full_cfg=cfg)
    await ctrl.run_forever()   # blocks — run inside asyncio.run() or as task
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import re
import textwrap
import time
from typing import Any

from .bot import TelegramBot

log = logging.getLogger("wp_hijack.telegram.controller")

_HELP = textwrap.dedent("""
<b>wp-Hijack Bot Commands</b>

🔍 <b>/scan</b> <code>https://target.com</code>
   Start full 10-phase vulnerability scan

🤖 <b>/agent</b> <code>https://target.com</code>
   Start autonomous AI agent (unlimited recon + exploit)

📊 <b>/status</b>
   Show current scan status or last scan summary

🐛 <b>/findings</b>
   List confirmed vulnerabilities from last scan

⛔ <b>/stop</b>
   Abort the running scan

📄 <b>/report</b>
   Re-send the last scan report PDF

⚙️ <b>/config</b>
   Show current scanner configuration

❓ <b>/help</b>
   Show this message
""").strip()

_WELCOME = (
    "👋 <b>wp-Hijack Bot</b> online!\n\n"
    "I let you launch and monitor WordPress security scans from Telegram.\n\n"
    + _HELP
)


class BotController:
    """
    Interactive Telegram bot controller.

    Parameters
    ----------
    tg_cfg : dict
        The ``telegram`` section of config.json.
    full_cfg : dict
        The complete loaded config (used for Scanner / Agent instantiation).
    """

    def __init__(self, tg_cfg: dict[str, Any], full_cfg: dict[str, Any]) -> None:
        self._tg_cfg = tg_cfg
        self._full_cfg = full_cfg
        self._token: str = tg_cfg.get("bot_token", "")
        self._allowed: set[int | str] = set(tg_cfg.get("allowed_chat_ids") or [])
        self._bot = TelegramBot(self._token)

        # Runtime state
        self._scan_task: asyncio.Task | None = None
        self._last_results: dict | None = None
        self._last_html: pathlib.Path | None = None
        self._last_pdf: pathlib.Path | None = None
        self._scan_target: str = ""
        self._offset: int = 0

    # ──────────────────────────────────────────────────────────────
    # Auth helper
    # ──────────────────────────────────────────────────────────────

    def _authorised(self, chat_id: int | str) -> bool:
        if not self._allowed:
            return True   # empty list → open to all (insecure — warn at startup)
        return int(chat_id) in {int(c) for c in self._allowed}

    # ──────────────────────────────────────────────────────────────
    # Main poll loop
    # ──────────────────────────────────────────────────────────────

    async def run_forever(self) -> None:
        """Long-poll forever, dispatching commands as they arrive."""
        if not self._token:
            log.error("BotController: no bot_token configured — aborting")
            return

        # Register command menu
        cmds = [
            {"command": "start",    "description": "Start / help"},
            {"command": "scan",     "description": "Scan <url>"},
            {"command": "agent",    "description": "Agent mode <url>"},
            {"command": "status",   "description": "Current status"},
            {"command": "findings", "description": "List findings"},
            {"command": "stop",     "description": "Abort scan"},
            {"command": "report",   "description": "Resend PDF report"},
            {"command": "config",   "description": "Show config"},
            {"command": "help",     "description": "Help"},
        ]
        await self._bot.set_bot_commands(cmds)
        me = await self._bot.get_me()
        name = me.get("result", {}).get("username", "wp-hijack-bot")

        log.info("BotController running as @%s, listening for commands…", name)
        if not self._allowed:
            log.warning("allowed_chat_ids is EMPTY — bot accepts commands from anyone!")

        print(f"[Telegram Bot] @{name} is online and waiting for commands.")

        while True:
            try:
                updates = await self._bot.get_updates(offset=self._offset, timeout=25)
                for update in updates:
                    self._offset = update["update_id"] + 1
                    msg = update.get("message", {})
                    if msg:
                        await self._dispatch(msg)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("Poll error: %s — retrying in 5s", exc)
                await asyncio.sleep(5)

    # ──────────────────────────────────────────────────────────────
    # Dispatcher
    # ──────────────────────────────────────────────────────────────

    async def _dispatch(self, msg: dict) -> None:
        chat_id = msg.get("chat", {}).get("id")
        text = (msg.get("text") or "").strip()
        if not chat_id or not text.startswith("/"):
            return

        if not self._authorised(chat_id):
            await self._bot.send_message(
                chat_id,
                "⛔ <b>Unauthorised.</b> Your chat ID is not in the allowed list.",
            )
            log.warning("Rejected command from unauthorised chat_id=%s", chat_id)
            return

        # Parse command + args
        parts = text.split(None, 1)
        cmd = parts[0].lower().lstrip("/").split("@")[0]
        args = parts[1].strip() if len(parts) > 1 else ""

        handlers = {
            "start":    self._cmd_start,
            "help":     self._cmd_help,
            "scan":     self._cmd_scan,
            "agent":    self._cmd_agent,
            "status":   self._cmd_status,
            "findings": self._cmd_findings,
            "stop":     self._cmd_stop,
            "report":   self._cmd_report,
            "config":   self._cmd_config,
        }

        handler = handlers.get(cmd)
        if handler:
            await handler(chat_id, args)
        else:
            await self._bot.send_message(
                chat_id,
                f"❓ Unknown command <code>/{cmd}</code>\n\n" + _HELP,
            )

    # ──────────────────────────────────────────────────────────────
    # Command handlers
    # ──────────────────────────────────────────────────────────────

    async def _cmd_start(self, chat_id: int | str, _: str) -> None:
        await self._bot.send_message(chat_id, _WELCOME)

    async def _cmd_help(self, chat_id: int | str, _: str) -> None:
        await self._bot.send_message(chat_id, _HELP)

    async def _cmd_scan(self, chat_id: int | str, args: str) -> None:
        target = self._parse_url(args)
        if not target:
            await self._bot.send_message(
                chat_id,
                "⚠️ <b>Usage:</b> <code>/scan https://target.com</code>"
            )
            return

        if self._scan_task and not self._scan_task.done():
            await self._bot.send_message(
                chat_id,
                f"⚠️ A scan of <code>{self._scan_target}</code> is already running.\n"
                "Use /stop to abort it first.",
            )
            return

        await self._bot.send_message(
            chat_id,
            f"🚀 <b>Launching scan</b>\n🎯 Target: <code>{target}</code>\n\n"
            "<i>You will receive phase updates. /status to check progress.</i>",
        )
        self._scan_target = target
        self._scan_task = asyncio.create_task(
            self._run_scan(target, chat_id, agent_mode=False)
        )

    async def _cmd_agent(self, chat_id: int | str, args: str) -> None:
        target = self._parse_url(args)
        if not target:
            await self._bot.send_message(
                chat_id,
                "⚠️ <b>Usage:</b> <code>/agent https://target.com</code>"
            )
            return

        if self._scan_task and not self._scan_task.done():
            await self._bot.send_message(
                chat_id,
                f"⚠️ A task is already running on <code>{self._scan_target}</code>.\n"
                "Use /stop to abort it first.",
            )
            return

        await self._bot.send_message(
            chat_id,
            f"🤖 <b>Launching Autonomous Agent</b>\n🎯 Target: <code>{target}</code>\n\n"
            "<i>The agent will plan → act → observe until assessment complete.</i>",
        )
        self._scan_target = target
        self._scan_task = asyncio.create_task(
            self._run_scan(target, chat_id, agent_mode=True)
        )

    async def _cmd_status(self, chat_id: int | str, _: str) -> None:
        if self._scan_task and not self._scan_task.done():
            await self._bot.send_message(
                chat_id,
                f"🔄 <b>Scan running</b>\n🎯 Target: <code>{self._scan_target}</code>\n"
                "<i>Use /findings to see discoveries so far, or /stop to abort.</i>",
            )
            return

        if self._last_results:
            r = self._last_results
            elapsed = r.get("elapsed", 0)
            confirmed = r.get("confirmed", [])
            c_total = len(confirmed)
            c_conf = sum(1 for cf in confirmed if getattr(cf, "status", None) and cf.status.value == "CONFIRMED")
            msg = (
                f"✅ <b>Last scan complete</b>\n"
                f"🎯 Target: <code>{r.get('target', '?')}</code>\n"
                f"⏱ Duration: <b>{elapsed:.0f}s</b>\n"
                f"🐛 Findings: <b>{c_conf}</b> confirmed / {c_total} total\n\n"
                "<i>Use /findings or /report to see details.</i>"
            )
        else:
            msg = "ℹ️ No scan has been run yet.\n\nUse <code>/scan https://target.com</code> to start."

        await self._bot.send_message(chat_id, msg)

    async def _cmd_findings(self, chat_id: int | str, _: str) -> None:
        if not self._last_results:
            await self._bot.send_message(chat_id, "ℹ️ No results yet. Run a scan first.")
            return

        confirmed = self._last_results.get("confirmed", [])
        if not confirmed:
            await self._bot.send_message(chat_id, "✅ No confirmed findings from last scan.")
            return

        lines = [f"🐛 <b>Confirmed Findings</b> ({len(confirmed)} total)\n"]
        _SEV_E = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
        for i, cf in enumerate(confirmed[:30], 1):
            f = cf.finding if hasattr(cf, "finding") else cf
            sev = getattr(f, "severity", "INFO")
            title = getattr(f, "title", "Unknown")
            component = getattr(f, "component", "?")
            cve = getattr(f, "cve", "")
            emoji = _SEV_E.get(str(sev).upper(), "⚪")
            cve_part = f" <code>{cve}</code>" if cve else ""
            lines.append(f"{i}. {emoji} <b>{title}</b>{cve_part}\n   📦 {component}")

        if len(confirmed) > 30:
            lines.append(f"\n<i>…and {len(confirmed) - 30} more. See full /report.</i>")

        await self._bot.send_message(chat_id, "\n".join(lines))

    async def _cmd_stop(self, chat_id: int | str, _: str) -> None:
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            await self._bot.send_message(
                chat_id,
                f"⛔ <b>Scan aborted</b>\n🎯 {self._scan_target}"
            )
        else:
            await self._bot.send_message(chat_id, "ℹ️ No scan is currently running.")

    async def _cmd_report(self, chat_id: int | str, _: str) -> None:
        if self._last_pdf and self._last_pdf.exists():
            await self._bot.send_document(
                chat_id, self._last_pdf,
                caption=f"📄 <b>Last scan report</b>\n🎯 {self._scan_target}",
            )
        elif self._last_html and self._last_html.exists():
            # Try to re-generate PDF
            try:
                from .pdf_playwright import html_to_pdf_playwright
                pdf = await html_to_pdf_playwright(self._last_html)
                self._last_pdf = pdf
                await self._bot.send_document(
                    chat_id, pdf,
                    caption=f"📄 <b>Report (converted now)</b>\n🎯 {self._scan_target}",
                )
            except Exception:
                await self._bot.send_document(
                    chat_id, self._last_html,
                    caption=f"🌐 <b>Report (HTML)</b>\n🎯 {self._scan_target}",
                )
        else:
            await self._bot.send_message(
                chat_id, "ℹ️ No report available yet. Run a scan first."
            )

    async def _cmd_config(self, chat_id: int | str, _: str) -> None:
        cfg = self._full_cfg
        ai = cfg.get("ai", {})
        sc = cfg.get("scanner", {})
        msg = (
            "⚙️ <b>Current Configuration</b>\n\n"
            f"🤖 AI: <b>{'enabled' if ai.get('enabled') else 'disabled'}</b>  "
            f"provider: <code>{ai.get('provider', '?')}</code>  "
            f"model: <code>{ai.get('model', '?')}</code>\n"
            f"🔢 Threads: <b>{sc.get('threads', '?')}</b>  "
            f"timeout: <b>{sc.get('timeout', '?')}s</b>\n"
            f"🕵 Stealth: <b>{'on' if sc.get('stealth_mode') else 'off'}</b>  "
            f"delay: <b>{sc.get('delay_between_requests', 0)}s</b>\n"
            f"📊 Reports: HTML={cfg.get('reporting', {}).get('html_enabled', True)}  "
            f"PDF={cfg.get('reporting', {}).get('pdf_enabled', True)}"
        )
        await self._bot.send_message(chat_id, msg)

    # ──────────────────────────────────────────────────────────────
    # Background scan runner
    # ──────────────────────────────────────────────────────────────

    async def _run_scan(
        self,
        target: str,
        notify_chat: int | str,
        agent_mode: bool = False,
    ) -> None:
        """Run a full scan / agent inside a background task, with Telegram updates."""
        from ..scanner import Scanner
        from ..telegram.notifier import TelegramNotifier
        from ..config import load_config

        notifier = TelegramNotifier(self._tg_cfg)
        notifier.notify_scan_start(target)

        try:
            if agent_mode:
                await self._run_agent(target, notifier, notify_chat)
            else:
                scanner = Scanner()
                scanner.set_notifier(notifier)
                results = await scanner.scan(target)
                self._last_results = results

                # Collect severity counts
                confirmed = results.get("confirmed", [])
                c_cnt = sum(1 for cf in confirmed if getattr(cf, "status", None) and cf.status.value == "CONFIRMED")
                critical = sum(
                    1 for cf in confirmed
                    if getattr(getattr(cf, "finding", cf), "severity", "") == "CRITICAL"
                )
                high = sum(
                    1 for cf in confirmed
                    if getattr(getattr(cf, "finding", cf), "severity", "") == "HIGH"
                )
                notifier.notify_scan_complete(
                    elapsed=results.get("elapsed", 0),
                    confirmed_count=c_cnt,
                    critical=critical,
                    high=high,
                )

                # Build report paths from target hostname
                import re as _re
                host = _re.sub(r"https?://", "", target).split("/")[0].replace(".", "_")
                reports_dir = pathlib.Path("reports")
                html_path = reports_dir / f"wp_hijack_{host}.html"
                pdf_path  = reports_dir / f"wp_hijack_{host}.pdf"

                if html_path.exists():
                    self._last_html = html_path
                    self._last_pdf  = pdf_path if pdf_path.exists() else None
                    await notifier.send_report(html_path, pdf_path if pdf_path.exists() else None)

        except asyncio.CancelledError:
            await self._bot.send_message(
                notify_chat,
                f"⛔ <b>Scan cancelled</b> by user.\n🎯 {target}",
            )
        except Exception as exc:
            log.exception("Error in background scan: %s", exc)
            await self._bot.send_message(
                notify_chat,
                f"❌ <b>Scan error</b>\n<code>{str(exc)[:500]}</code>",
            )

    async def _run_agent(
        self,
        target: str,
        notifier: Any,
        notify_chat: int | str,
    ) -> None:
        """Run autonomous agent mode."""
        from ..agent.agent_loop import AutonomousAgent

        ai_cfg = self._full_cfg.get("ai", {})
        agent_cfg = self._full_cfg.get("agent", {})
        agent = AutonomousAgent(target=target, ai_cfg=ai_cfg, agent_cfg=agent_cfg)
        agent.set_notifier(notifier)
        session = await agent.run()
        await self._bot.send_message(
            notify_chat,
            f"✅ <b>Agent complete</b> — {len(session.steps)} steps\n🎯 {target}",
        )

    # ──────────────────────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_url(text: str) -> str | None:
        """Extract and normalise a URL from user input."""
        text = text.strip()
        if not text:
            return None
        if not re.match(r"^https?://", text, re.I):
            text = "http://" + text
        return text.rstrip("/")
