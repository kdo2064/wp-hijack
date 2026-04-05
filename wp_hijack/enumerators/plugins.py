"""Plugin enumeration — passive HTML parse + aggressive readme.txt probe."""
from __future__ import annotations
import re
import asyncio
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup

_PLUGIN_PATH_RE = re.compile(
    r'/wp-content/plugins/([a-z0-9_-]+)/', re.I
)
_STABLE_TAG_RE  = re.compile(r'Stable tag:\s*([\d.]+)', re.I)
_README_VER_RE  = re.compile(r'=== .+? ===.*?Stable tag:\s*([\d.]+)', re.I | re.S)

# Top common WordPress plugins to probe aggressively even when passive scan finds nothing
_COMMON_PLUGIN_SLUGS: list[str] = [
    "woocommerce", "contact-form-7", "yoast-seo", "elementor", "akismet",
    "wordfence", "wp-super-cache", "jetpack", "wpforms-lite", "all-in-one-seo-pack",
    "really-simple-ssl", "litespeed-cache", "updraftplus", "wp-optimize",
    "redirection", "classic-editor", "duplicate-post", "loginizer",
    "wp-mail-smtp", "mailchimp-for-wp", "ninja-forms", "gravity-forms",
    "advanced-custom-fields", "wp-fastest-cache", "autoptimize",
    "limit-login-attempts-reloaded", "easy-wp-smtp", "wp-rocket",
    "buddypress", "bbpress", "wp-statistics", "revslider", "slider-revolution",
    "nextgen-gallery", "broken-link-checker", "google-analytics-for-wordpress",
    "the-events-calendar", "tablepress", "user-role-editor",
    "wp-user-avatar", "ultimate-member", "memberpress",
    "give", "learnpress", "lms", "tutor", "learndash",
    "backwpup", "duplicator", "all-in-one-wp-migration",
    "better-wp-security", "ithemes-security", "sucuri-scanner",
]


@dataclass
class PluginInfo:
    slug: str
    version: str | None = None
    path: str = ""
    readme_found: bool = False
    extra: dict = field(default_factory=dict)


async def enumerate_plugins(
    http,
    base_url: str,
    home_html: str,
    *,
    aggressive: bool = True,
    slugs_hint: list[str] | None = None,
) -> list[PluginInfo]:
    """
    Step 1 — Passive: extract plugin slugs from home page HTML paths.
    Step 2 — Aggressive: probe /wp-content/plugins/{slug}/readme.txt for version.
    """
    base = base_url.rstrip("/")
    found: dict[str, PluginInfo] = {}

    # ── Passive ─────────────────────────────────────────────────────────────────
    for slug in _PLUGIN_PATH_RE.findall(home_html):
        if slug not in found:
            found[slug] = PluginInfo(slug=slug, path=f"/wp-content/plugins/{slug}/")

    # Extra slugs via hints (from previous scans or user supplies)
    if slugs_hint:
        for slug in slugs_hint:
            if slug not in found:
                found[slug] = PluginInfo(slug=slug)

    # ── Aggressive: version from readme.txt ─────────────────────────────────────
    if aggressive:
        # Always probe common slug wordlist in addition to passively discovered ones
        for slug in _COMMON_PLUGIN_SLUGS:
            if slug not in found:
                found[slug] = PluginInfo(slug=slug)

        async def _probe(slug: str, url: str) -> None:
            try:
                r = await http.get(url, timeout=8)
                if r.status_code == 200:
                    found[slug].readme_found = True
                    if (m := _STABLE_TAG_RE.search(r.text)):
                        found[slug].version = m.group(1)
            except Exception:
                pass

        await asyncio.gather(
            *(_probe(slug, f"{base}/wp-content/plugins/{slug}/readme.txt") for slug in found)
        )

    # Return only plugins confirmed to exist (readme found) or found passively
    return [p for p in found.values() if p.readme_found or p.path]
