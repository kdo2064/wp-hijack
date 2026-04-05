"""User enumeration — 4 methods: author archives, REST API, login oracle, oEmbed."""
from __future__ import annotations
import re
import asyncio
import json
from dataclasses import dataclass, field

import httpx

_AUTHOR_SLUG_RE  = re.compile(r'/author/([a-z0-9_.-]+)/', re.I)
_AUTHOR_CLASS_RE = re.compile(r'author-([a-z0-9_.-]+)', re.I)


@dataclass
class UserInfo:
    id: int | None = None
    login: str | None = None
    display_name: str | None = None
    email: str | None = None
    source: str = ""


async def enumerate_users(http, base_url: str, home_html: str = "") -> list[UserInfo]:
    base = base_url.rstrip("/")
    users: dict[str, UserInfo] = {}   # keyed by login

    async def _rest_api():
        try:
            r = await http.get(f"{base}/wp-json/wp/v2/users", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    for entry in data:
                        login = entry.get("slug") or entry.get("name", "")
                        if login:
                            users[login] = UserInfo(
                                id=entry.get("id"),
                                login=login,
                                display_name=entry.get("name"),
                                source="REST API",
                            )
        except Exception:
            pass

    async def _author_archives():
        for uid in range(1, 6):
            try:
                r = await http.get(f"{base}/?author={uid}", timeout=8)
                if r.status_code == 200:
                    # Check redirect URL path (WordPress redirects /?author=1 → /author/username/)
                    for slug in _AUTHOR_SLUG_RE.findall(str(r.url)):
                        if slug not in users:
                            users[slug] = UserInfo(id=uid, login=slug, source="author archive")
                    # Also check response body (some caching/SEO plugins skip redirect)
                    for slug in _AUTHOR_SLUG_RE.findall(r.text):
                        if slug not in users:
                            users[slug] = UserInfo(id=uid, login=slug, source="author archive")
                    # Parse class="author-<login>" from response body
                    for slug in _AUTHOR_CLASS_RE.findall(r.text):
                        if slug != "by" and slug not in users:
                            users[slug] = UserInfo(id=uid, login=slug, source="author CSS class")
            except Exception:
                pass

    async def _oembed():
        try:
            r = await http.get(f"{base}/wp-json/oembed/1.0/embed?url={base}", timeout=8)
            if r.status_code == 200:
                data = r.json()
                author = data.get("author_name") or data.get("author_url", "")
                if author and author not in users:
                    users[author] = UserInfo(login=author, source="oEmbed")
        except Exception:
            pass

    async def _login_oracle():
        """username enumeration via wp-login error messages"""
        test_names = ["admin", "administrator", "editor", "webmaster"]
        for name in test_names:
            try:
                r = await http.post(
                    f"{base}/wp-login.php",
                    data={"log": name, "pwd": "invalid_pw_12345!", "wp-submit": "Log+In"},
                    timeout=8,
                )
                body = r.text.lower()
                # WordPress discloses "incorrect password" vs "invalid username"
                if "incorrect password" in body or "the password you entered" in body:
                    if name not in users:
                        users[name] = UserInfo(login=name, source="login oracle")
            except Exception:
                pass

    await asyncio.gather(_rest_api(), _author_archives(), _oembed(), _login_oracle())

    return list(users.values())
