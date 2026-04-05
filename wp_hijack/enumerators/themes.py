"""Theme enumeration via style.css version header."""

from __future__ import annotations

import re

import asyncio

from dataclasses import dataclass, field



_THEME_PATH_RE  = re.compile(r'/wp-content/themes/([a-z0-9_-]+)/', re.I)

_THEME_NAME_RE  = re.compile(r'Theme Name:\s*(.+)', re.I)

_THEME_VER_RE   = re.compile(r'Version:\s*([\d.a-z-]+)', re.I)

_THEME_AUTHOR_RE= re.compile(r'Author:\s*(.+)', re.I)




_COMMON_THEME_SLUGS: list[str] = [

    "twentytwentyfive", "twentytwentyfour", "twentytwentythree",

    "twentytwentytwo", "twentytwentyone", "twentytwenty", "twentynineteen",

    "twentyseventeen", "astra", "generatepress", "oceanwp", "hello-elementor",

    "neve", "kadence", "blocksy", "storefront", "avada", "divi",

    "porto", "flatsome", "salient", "enfold", "bridge",

]





@dataclass

class ThemeInfo:

    slug: str

    name: str | None = None

    version: str | None = None

    author: str | None = None

    active: bool = False

    style_found: bool = False





async def enumerate_themes(

    http, base_url: str, home_html: str

) -> list[ThemeInfo]:

    base = base_url.rstrip("/")

    found: dict[str, ThemeInfo] = {}



    for slug in _THEME_PATH_RE.findall(home_html):

        if slug not in found:

            found[slug] = ThemeInfo(slug=slug)




    for slug in _COMMON_THEME_SLUGS:

        if slug not in found:

            found[slug] = ThemeInfo(slug=slug)



    async def _probe(slug: str) -> None:

        try:

            url = f"{base}/wp-content/themes/{slug}/style.css"

            r = await http.get(url, timeout=8)

            if r.status_code == 200:

                t = found[slug]

                t.style_found = True

                if (m := _THEME_NAME_RE.search(r.text)):

                    t.name = m.group(1).strip()

                if (m := _THEME_VER_RE.search(r.text)):

                    t.version = m.group(1).strip()

                if (m := _THEME_AUTHOR_RE.search(r.text)):

                    t.author = m.group(1).strip()

        except Exception:

            pass



    await asyncio.gather(*(_probe(s) for s in found))


    return [t for t in found.values() if t.style_found]

