"""Joomla version detection."""

from __future__ import annotations

import re

import httpx

from bs4 import BeautifulSoup

from .detector import CMSInfo, CMSType



_JOOMLA_XML_RE   = re.compile(r'<version>([\d.]+)</version>', re.I)

_JOOMLA_GEN_RE   = re.compile(r'Joomla!\s*([\d.]+)', re.I)





async def detect_joomla(http, base_url: str, home_resp: httpx.Response | None = None) -> CMSInfo:

    info = CMSInfo(cms=CMSType.JOOMLA)

    signals: list[tuple[str, int]] = []

    base = base_url.rstrip("/")




    html = ""

    if home_resp and isinstance(home_resp, httpx.Response):

        try:

            html = home_resp.text

        except Exception:

            pass

    if html:

        soup = BeautifulSoup(html, "lxml")

        gen = soup.find("meta", attrs={"name": "generator"})

        content = gen.get("content", "") if gen else ""

        if "Joomla" in content:

            signals.append(("meta generator Joomla", 30))

            if (m := _JOOMLA_GEN_RE.search(content)):

                info.version = m.group(1)

                signals.append(("meta version", 20))




    try:

        r = await http.get(f"{base}/administrator/manifests/files/joomla.xml", timeout=8)

        if r.status_code == 200 and "joomla" in r.text.lower():

            signals.append(("joomla.xml manifest", 25))

            if (m := _JOOMLA_XML_RE.search(r.text)) and not info.version:

                info.version = m.group(1)

                signals.append(("manifest version", 20))

    except Exception:

        pass




    try:

        r = await http.get(f"{base}/components/", timeout=6)

        if r.status_code in (200, 403):

            signals.append(("components/ accessible", 10))

    except Exception:

        pass



    info.confidence = min(sum(p for _, p in signals), 100)

    info.signals = [n for n, _ in signals]

    return info

