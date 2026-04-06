"""
TelegramNotifier — broadcasts wp-Hijack scan events to all allowed Telegram chats.

Instantiate once per scan run and call the `notify_*` methods at each stage.
All methods are async-safe fire-and-forget via `asyncio.create_task()`.
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import time
from typing import Any

from .bot import TelegramBot

log = logging.getLogger("wp_hijack.telegram.notifier")

# Severity → emoji map
_SEV_EMOJI: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def _esc(text: str) -> str:
    """Escape HTML special chars so Telegram renders them correctly."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


class TelegramNotifier:
    """
    Sends real-time scan progress & final report PDF to Telegram.

    Parameters
    ----------
    cfg : dict
        The ``telegram`` section of config.json.
    """

    def __init__(self, cfg: dict[str, Any]) -> None:
        self._enabled: bool = bool(cfg.get("enabled", False))
        token: str = cfg.get("bot_token", "")
        self._chat_ids: list[int | str] = cfg.get("allowed_chat_ids") or []
        self._notify_phases: bool = bool(cfg.get("notify_scan_phases", True))
        self._notify_steps: bool = bool(cfg.get("notify_agent_steps", True))
        self._notify_findings: bool = bool(cfg.get("notify_findings", True))
        self._send_report: bool = bool(cfg.get("send_report_pdf", True))
        self._playwright_pdf: bool = bool(cfg.get("pdf_via_playwright", True))
        self._silent: bool = bool(cfg.get("silent_mode", False))

        self._bot: TelegramBot | None = None
        if self._enabled and token and self._chat_ids:
            self._bot = TelegramBot(token)
        elif self._enabled:
            log.warning(
                "Telegram enabled but bot_token or allowed_chat_ids missing — notifications disabled."
            )

        self._scan_start: float = 0.0
        self._target: str = ""
        self._step_count: int = 0

    # ──────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────

    def _fire(self, coro: Any) -> None:
        """Schedule a coroutine as a background asyncio task (non-blocking)."""
        if not self._bot:
            return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(coro)
            else:
                loop.run_until_complete(coro)
        except Exception as exc:
            log.debug("Telegram fire error: %s", exc)

    async def _broadcast(self, text: str, silent: bool | None = None) -> None:
        """Send *text* to every allowed chat ID."""
        if not self._bot:
            return
        _silent = self._silent if silent is None else silent
        for cid in self._chat_ids:
            try:
                await self._bot.send_message(cid, text, silent=_silent)
            except Exception as exc:
                log.debug("Telegram send error (chat=%s): %s", cid, exc)

    async def _broadcast_document(
        self,
        file_path: pathlib.Path,
        caption: str = "",
    ) -> None:
        if not self._bot:
            return
        for cid in self._chat_ids:
            try:
                await self._bot.send_document(cid, file_path, caption=caption)
            except Exception as exc:
                log.debug("Telegram doc error (chat=%s): %s", cid, exc)

    # ──────────────────────────────────────────────────────────────
    # Public notification methods
    # ──────────────────────────────────────────────────────────────

    def notify_scan_start(self, target: str) -> None:
        """Called when the scan begins."""
        if not self._bot or not self._notify_phases:
            return
        self._target = target
        self._scan_start = time.monotonic()
        msg = (
            "🔍 <b>wp-Hijack Scan Started</b>\n\n"
            f"🎯 Target: <code>{_esc(target)}</code>\n"
            "📡 Running 10-phase security assessment…\n\n"
            "<i>You'll receive updates for each phase and final report.</i>"
        )
        self._fire(self._broadcast(msg))

    def notify_phase(self, phase: str, detail: str = "") -> None:
        """Called at the start/end of each scan phase."""
        if not self._bot or not self._notify_phases:
            return
        elapsed = time.monotonic() - self._scan_start if self._scan_start else 0
        elapsed_str = f"{elapsed:.0f}s" if elapsed < 60 else f"{elapsed / 60:.1f}m"
        msg = (
            f"⚙️ <b>{_esc(phase)}</b>\n"
            + (f"<code>{_esc(detail[:300])}</code>" if detail else "")
            + f"\n<i>Elapsed: {elapsed_str}</i>"
        )
        self._fire(self._broadcast(msg, silent=True))   # phase updates are silent

    def notify_finding(self, severity: str, title: str, component: str, cve: str = "") -> None:
        """Called when a vulnerability is found/confirmed."""
        if not self._bot or not self._notify_findings:
            return
        emoji = _SEV_EMOJI.get(severity.upper(), "⚪")
        cve_part = f"  <code>{_esc(cve)}</code>" if cve else ""
        msg = (
            f"{emoji} <b>[{_esc(severity)}]</b> {_esc(title)}\n"
            f"📦 Component: <code>{_esc(component)}</code>{cve_part}"
        )
        # Findings are silent to avoid spam; critical ones are loud
        silent = self._silent or severity.upper() not in {"CRITICAL", "HIGH"}
        self._fire(self._broadcast(msg, silent=silent))

    def notify_agent_step(
        self,
        step: int,
        thought: str,
        action: str,
        tool: str | None = None,
        result_summary: str | None = None,
    ) -> None:
        """Called after each autonomous agent step."""
        if not self._bot or not self._notify_steps:
            return
        self._step_count += 1
        tool_line = f"\n🔧 Tool: <code>{_esc(tool)}</code>" if tool else ""
        result_line = (
            f"\n📤 <code>{_esc(result_summary[:200])}</code>"
            if result_summary else ""
        )
        msg = (
            f"🤖 <b>Agent Step {step}</b>\n"
            f"💭 <i>{_esc(thought[:200])}</i>\n"
            f"▶ Action: <b>{_esc(action)}</b>"
            + tool_line
            + result_line
        )
        self._fire(self._broadcast(msg, silent=True))

    def notify_scan_complete(
        self,
        elapsed: float,
        confirmed_count: int,
        critical: int = 0,
        high: int = 0,
    ) -> None:
        """Called when the full scan pipeline finishes."""
        if not self._bot or not self._notify_phases:
            return
        mins = f"{elapsed / 60:.1f}m" if elapsed >= 60 else f"{elapsed:.0f}s"
        sev_line = ""
        if critical or high:
            sev_line = f"\n🔴 Critical: <b>{critical}</b>  🟠 High: <b>{high}</b>"
        msg = (
            f"✅ <b>Scan Complete</b> — {_esc(self._target)}\n\n"
            f"⏱ Duration: <b>{mins}</b>\n"
            f"🐛 Confirmed findings: <b>{confirmed_count}</b>"
            + sev_line
            + "\n\n<i>Building report…</i>"
        )
        self._fire(self._broadcast(msg))

    def notify_error(self, context: str, error: str) -> None:
        """Notify about a non-fatal error during scanning."""
        if not self._bot:
            return
        msg = (
            f"⚠️ <b>Warning</b> — {_esc(context)}\n"
            f"<code>{_esc(str(error)[:300])}</code>"
        )
        self._fire(self._broadcast(msg, silent=True))

    async def send_report(
        self,
        html_path: pathlib.Path | str,
        pdf_path: pathlib.Path | str | None = None,
    ) -> None:
        """
        Convert the HTML report to PDF (via Playwright) and send to all chats.
        Falls back to sending the HTML if conversion fails.
        """
        if not self._bot or not self._send_report:
            return

        html_path = pathlib.Path(html_path)
        target_name = _esc(self._target.replace("https://", "").replace("http://", ""))

        # Try Playwright PDF first
        if self._playwright_pdf:
            try:
                from .pdf_playwright import html_to_pdf_playwright
                out_pdf = pathlib.Path(pdf_path) if pdf_path else html_path.with_suffix(".pdf")
                log.info("Converting HTML → PDF via Playwright…")
                out_pdf = await html_to_pdf_playwright(html_path, out_pdf)
                caption = (
                    f"📄 <b>wp-Hijack Report</b>\n"
                    f"🎯 {target_name}\n"
                    f"📦 Full vulnerability assessment — <i>PDF via Playwright</i>"
                )
                await self._broadcast_document(out_pdf, caption=caption)
                return
            except Exception as exc:
                log.warning("Playwright PDF failed (%s), falling back to reportlab PDF / HTML", exc)

        # Fallback: reportlab PDF
        if pdf_path and pathlib.Path(str(pdf_path)).exists():
            caption = (
                f"📄 <b>wp-Hijack Report</b>\n🎯 {target_name}"
            )
            await self._broadcast_document(pathlib.Path(str(pdf_path)), caption=caption)
            return

        # Last resort: send HTML
        if html_path.exists():
            caption = f"🌐 <b>wp-Hijack Report (HTML)</b>\n🎯 {target_name}"
            await self._broadcast_document(html_path, caption=caption)
