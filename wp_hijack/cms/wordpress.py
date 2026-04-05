"""WordPress multi-signal version detection."""
from __future__ import annotations
import re
import hashlib
import asyncio
import httpx
from bs4 import BeautifulSoup
from .detector import CMSInfo, CMSType


_WP_GENERATOR_RE = re.compile(r'content=["\']WordPress\s+([\d.]+)["\']', re.I)
_WP_VER_QUERY_RE = re.compile(r'\?ver=([\d.]+)')
_STABLE_TAG_RE   = re.compile(r'Stable tag:\s*([\d.]+)', re.I)
_RSS_VERSION_RE  = re.compile(r'<generator>https?://wordpress\.(?:org|com)/\?v=([\d.]+)', re.I)
_ATOM_VERSION_RE = re.compile(r'<generator uri="https?://wordpress\.(?:org|com)/" version="([\d.]+)"', re.I)

# Known login.php content hashes → WP versions (tiny sample; extend via vulns.json)
_LOGIN_HASHES: dict[str, str] = {}


async def detect_wordpress(http, base_url: str, home_resp: httpx.Response | None = None) -> CMSInfo:
    info = CMSInfo(cms=CMSType.WORDPRESS)
    signals: list[tuple[str, int]] = []   # (signal_name, confidence_pts)

    base = base_url.rstrip("/")

    # ── Signal 1: meta generator from home page ────────────────────────────────
    html = ""
    if home_resp is not None and isinstance(home_resp, httpx.Response):
        try:
            html = home_resp.text
        except Exception:
            html = ""

    if html:
        soup = BeautifulSoup(html, "lxml")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and "WordPress" in (gen.get("content", "")):
            signals.append(("meta generator", 30))
            if (m := _WP_GENERATOR_RE.search(gen.get("content", ""))):
                info.version = m.group(1)
                signals.append(("meta version", 20))

        # wp-content path
        if "wp-content" in html or "wp-includes" in html:
            signals.append(("wp-content/wp-includes paths", 20))

        # ?ver= query string on scripts/styles
        vers = _WP_VER_QUERY_RE.findall(html)
        if vers:
            count: dict[str, int] = {}
            for v in vers:
                count[v] = count.get(v, 0) + 1
            dominant = max(count, key=lambda k: count[k])
            if not info.version:
                info.version = dominant
            signals.append(("?ver= query strings", 10))

    # ── Signal 2: readme.html ──────────────────────────────────────────────────
    try:
        r = await http.get(f"{base}/readme.html", timeout=8)
        if r.status_code == 200 and "WordPress" in r.text:
            signals.append(("readme.html present", 15))
            if (m := re.search(r'<br />\s*[Vv]ersion\s*([\d.]+)', r.text)):
                if not info.version:
                    info.version = m.group(1)
                signals.append(("readme.html version", 15))
    except Exception:
        pass

    # ── Signal 3: RSS feed ─────────────────────────────────────────────────────
    async def _rss():
        try:
            r = await http.get(f"{base}/?feed=rss2", timeout=8)
            if r.status_code == 200:
                if m := _RSS_VERSION_RE.search(r.text):
                    return m.group(1)
        except Exception:
            pass
        return None

    # ── Signal 4: Atom feed ────────────────────────────────────────────────────
    async def _atom():
        try:
            r = await http.get(f"{base}/?feed=atom", timeout=8)
            if r.status_code == 200:
                if m := _ATOM_VERSION_RE.search(r.text):
                    return m.group(1)
        except Exception:
            pass
        return None

    # ── Signal 5: wp-login.php ( checks for wp-login existence )
    async def _login():
        try:
            r = await http.get(f"{base}/wp-login.php", timeout=8)
            return r.status_code in (200, 302, 301)
        except Exception:
            return False

    rss_ver, atom_ver, has_login = await asyncio.gather(_rss(), _atom(), _login())

    if rss_ver:
        if not info.version:
            info.version = rss_ver
        signals.append(("RSS generator version", 15))

    if atom_ver:
        if not info.version:
            info.version = atom_ver
        signals.append(("Atom feed version", 15))

    if has_login:
        signals.append(("wp-login.php accessible", 10))

    # ── Signal 6: REST API discovery (/wp-json/) ────────────────────────────
    try:
        r_api = await http.get(f"{base}/wp-json/", timeout=8)
        if r_api.status_code == 200:
            try:
                api_json = r_api.json()
                if isinstance(api_json, dict) and ("namespaces" in api_json or "routes" in api_json):
                    signals.append(("wp-json REST API endpoint", 40))
                    # Extract version from API if available
                    if not info.version and api_json.get("version"):
                        info.version = api_json["version"]
            except Exception:
                if "wp/v2" in r_api.text or "WordPress" in r_api.text:
                    signals.append(("wp-json REST API endpoint (body match)", 30))
    except Exception:
        pass

    # ── Signal 7: Link header pointing to REST API ─────────────────────────
    if html and "rel=\"https://api.w.org/\"" in html:
        signals.append(("Link header: wp REST API relation", 25))

    # Also check home_resp headers if available
    if home_resp is not None and isinstance(home_resp, httpx.Response):
        link_hdr = home_resp.headers.get("link", "")
        if "api.w.org" in link_hdr and ("Link header: wp REST API relation", 25) not in signals:
            signals.append(("Link header: wp REST API relation", 25))

    # ── Confidence calculation ─────────────────────────────────────────────────
    total = sum(pts for _, pts in signals)
    info.confidence = min(total, 100)
    info.signals = [name for name, _ in signals]

    return info
