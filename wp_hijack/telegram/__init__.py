"""
wp-Hijack Telegram Integration
────────────────────────────────────────────────────────────
Provides:
  • TelegramBot      — raw async Telegram Bot API client
  • TelegramNotifier — broadcasts scan/agent progress to all allowed chat IDs
  • BotController    — long-poll listener; users control scans via /@commands
  • html_to_pdf_playwright — convert HTML report → beautiful PDF via Playwright
"""

from .bot        import TelegramBot
from .notifier   import TelegramNotifier
from .controller import BotController

__all__ = ["TelegramBot", "TelegramNotifier", "BotController"]
