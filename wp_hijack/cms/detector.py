"""CMS detection — WordPress, Joomla, Drupal, and generic PHP."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

import re
import httpx
from bs4 import BeautifulSoup


class CMSType(str, Enum):
    WORDPRESS = "WordPress"
    JOOMLA    = "Joomla"
    DRUPAL    = "Drupal"
    PHP       = "PHP"
    UNKNOWN   = "Unknown"


@dataclass
class CMSInfo:
    cms: CMSType = CMSType.UNKNOWN
    version: str | None = None
    confidence: int = 0          # 0-100
    signals: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    server: str | None = None
    php_version: str | None = None
    extra: dict = field(default_factory=dict)


async def detect_cms(http, base_url: str) -> CMSInfo:
    """
    Multi-signal CMS detection. Returns the best CMSInfo found.
    Runs WordPress, Joomla, Drupal probes concurrently.
    """
    import asyncio
    from .wordpress import detect_wordpress
    from .joomla    import detect_joomla
    from .drupal    import detect_drupal

    # Fetch home page once and share
    try:
        home_resp: httpx.Response = await http.get(base_url)
    except Exception:
        home_resp = None  # type: ignore[assignment]

    results = await asyncio.gather(
        detect_wordpress(http, base_url, home_resp),
        detect_joomla(http, base_url, home_resp),
        detect_drupal(http, base_url, home_resp),
        return_exceptions=True,
    )

    best: CMSInfo = CMSInfo()
    for r in results:
        if isinstance(r, CMSInfo) and r.confidence > best.confidence:
            best = r

    # Enrich with server/PHP from home page headers
    if home_resp is not None and isinstance(home_resp, httpx.Response):
        hdrs = dict(home_resp.headers)
        best.headers = hdrs
        best.server = hdrs.get("server")
        x_pow = hdrs.get("x-powered-by", "")
        if (m := re.search(r"PHP/([\d.]+)", x_pow)):
            best.php_version = m.group(1)

    return best
