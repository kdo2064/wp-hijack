"""
TelegramBot — async Telegram Bot API client.

Uses httpx directly (already a project dependency), no python-telegram-bot needed.

Usage::

    bot = TelegramBot(token="123456:ABC...")
    await bot.send_message(chat_id=12345, text="Hello!")
    await bot.send_document(chat_id=12345, file_path=Path("report.pdf"), caption="Scan report")
"""

from __future__ import annotations

import asyncio
import logging
import mimetypes
import pathlib
from typing import Any

import httpx

log = logging.getLogger("wp_hijack.telegram.bot")

_BASE = "https://api.telegram.org/bot{token}/{method}"
_MAX_MSG_LEN = 4096


class TelegramBot:
    """Thin async wrapper around the Telegram Bot HTTP API."""

    def __init__(self, token: str, timeout: int = 30) -> None:
        self.token = token
        self.timeout = timeout
        self._base = f"https://api.telegram.org/bot{token}"

    # ──────────────────────────────────────────────────────────────
    # Low-level helpers
    # ──────────────────────────────────────────────────────────────
    async def _call(self, method: str, **kwargs: Any) -> dict:
        """POST to a Bot API method; return JSON result dict."""
        url = f"{self._base}/{method}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, **kwargs)
                data = resp.json()
                if not data.get("ok"):
                    log.warning("Telegram API error [%s]: %s", method, data.get("description"))
                return data
        except Exception as exc:
            log.error("Telegram request failed (%s): %s", method, exc)
            return {"ok": False, "description": str(exc)}

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    async def send_message(
        self,
        chat_id: int | str,
        text: str,
        parse_mode: str = "HTML",
        silent: bool = False,
        disable_preview: bool = True,
    ) -> dict:
        """Send a text message (auto-splits if > 4096 chars)."""
        chunks = [text[i : i + _MAX_MSG_LEN] for i in range(0, len(text), _MAX_MSG_LEN)]
        result: dict = {}
        for chunk in chunks:
            result = await self._call(
                "sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": chunk,
                    "parse_mode": parse_mode,
                    "disable_notification": silent,
                    "disable_web_page_preview": disable_preview,
                },
            )
            if len(chunks) > 1:
                await asyncio.sleep(0.35)   # avoid flood-limit
        return result

    async def send_document(
        self,
        chat_id: int | str,
        file_path: pathlib.Path | str,
        caption: str = "",
        parse_mode: str = "HTML",
        silent: bool = False,
    ) -> dict:
        """Upload and send a file (PDF, HTML, …)."""
        file_path = pathlib.Path(file_path)
        mime = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        with file_path.open("rb") as fh:
            return await self._call(
                "sendDocument",
                data={
                    "chat_id": str(chat_id),
                    "caption": caption[:1024],
                    "parse_mode": parse_mode,
                    "disable_notification": str(silent).lower(),
                },
                files={"document": (file_path.name, fh, mime)},
            )

    async def send_photo(
        self,
        chat_id: int | str,
        photo_path: pathlib.Path | str,
        caption: str = "",
    ) -> dict:
        photo_path = pathlib.Path(photo_path)
        with photo_path.open("rb") as fh:
            return await self._call(
                "sendPhoto",
                data={"chat_id": str(chat_id), "caption": caption[:1024]},
                files={"photo": (photo_path.name, fh, "image/png")},
            )

    async def get_updates(self, offset: int = 0, timeout: int = 30) -> list[dict]:
        """Long-poll for new updates."""
        data = await self._call(
            "getUpdates",
            json={"offset": offset, "timeout": timeout, "allowed_updates": ["message"]},
        )
        return data.get("result", [])

    async def get_me(self) -> dict:
        """Return bot info."""
        return await self._call("getMe")

    async def set_bot_commands(self, commands: list[dict]) -> dict:
        """Register bot command menu."""
        return await self._call("setMyCommands", json={"commands": commands})

    async def answer_and_notify(
        self,
        chat_id: int | str,
        text: str,
        silent: bool = False,
    ) -> dict:
        """Convenience wrapper — same as send_message with sensible defaults."""
        return await self.send_message(chat_id, text, silent=silent)
