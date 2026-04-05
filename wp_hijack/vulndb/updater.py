"""NVD bulk feed downloader — no API key required."""

from __future__ import annotations

import asyncio

import gzip

import json

import pathlib

import re

import datetime

from typing import Any



import httpx

import aiofiles



from .db import load_bundled, init_db



_NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"

_WP_KEYWORDS = {

    "wordpress", "wp-", "woocommerce", "elementor", "wpbakery",

    "yoast", "jetpack", "contact-form-7",

}



_LOCAL_DIR  = pathlib.Path(__file__).parent

_CACHE_FILE = _LOCAL_DIR / "nvd_cache.json"





async def _download_year(year: int, client: httpx.AsyncClient) -> list[dict]:

    """Download and parse NVD feed for one year. Returns WP-relevant entries."""

    url = _NVD_BASE.format(year=year)

    try:

        resp = await client.get(url, timeout=120)

        if resp.status_code != 200:

            return []

        raw_gz = resp.content

        raw_json = gzip.decompress(raw_gz)

        data = json.loads(raw_json)

        items = data.get("CVE_Items", [])

        wp_items = []

        for item in items:

            cve_data = item.get("cve", {})

            desc_list = cve_data.get("description", {}).get("description_data", [])

            desc = " ".join(d.get("value", "") for d in desc_list).lower()

            if any(kw in desc for kw in _WP_KEYWORDS):

                wp_items.append(_parse_nvd_item(item))

        return [i for i in wp_items if i is not None]

    except Exception as exc:

        return []





def _parse_nvd_item(item: dict) -> dict | None:

    try:

        cve_node    = item["cve"]

        cve_id      = cve_node["CVE_data_meta"]["ID"]

        desc_data   = cve_node["description"]["description_data"]

        description = next(

            (d["value"] for d in desc_data if d.get("lang") == "en"), ""

        )

        refs = [

            r["url"]

            for r in cve_node.get("references", {}).get("reference_data", [])

        ]

        impact        = item.get("impact", {})

        cvss_v3       = impact.get("baseMetricV3", {}).get("cvssV3", {})

        cvss_v2       = impact.get("baseMetricV2", {}).get("cvssV2", {})

        cvss_score    = float(cvss_v3.get("baseScore") or cvss_v2.get("baseScore") or 5.0)

        severity      = cvss_v3.get("baseSeverity") or cvss_v2.get("severity") or "MEDIUM"




        slug = _extract_wp_slug(description)



        return {

            "id":          cve_id,

            "cve":         cve_id,

            "title":       description[:120],

            "description": description,

            "severity":    severity.upper(),

            "cvss":        cvss_score,

            "component":   slug or "",

            "component_type": "plugin",

            "affected_versions": [],

            "fixed_version": None,

            "references":  refs,

            "remediation": "Update to the latest version",

            "updated_at":  item.get("lastModifiedDate", ""),

        }

    except Exception:

        return None





_SLUG_RE = re.compile(

    r'(?:plugin|theme)\s+["\']?([a-z0-9_-]+)["\']?', re.I

)





def _extract_wp_slug(text: str) -> str | None:

    m = _SLUG_RE.search(text)

    return m.group(1).lower() if m else None





async def update_vulndb(

    years: list[int] | None = None,

    db_path: pathlib.Path | None = None,

) -> dict[str, Any]:

    """
    Download NVD bulk feeds for given years and merge WordPress-related entries
    into the local database. No API key needed.

    Returns summary dict.
    """

    from .db import load_bundled, init_db

    import pathlib as pl



    if db_path is None:

        db_path = pl.Path(__file__).parent / "wp_hijack.db"



    await init_db(db_path)


    bundled_count = await load_bundled(db_path)



    if years is None:

        current = datetime.datetime.now().year

        years = list(range(2020, current + 1))



    total_new = 0

    async with httpx.AsyncClient(follow_redirects=True, http2=False) as client:

        for year in years:

            items = await _download_year(year, client)

            if items:


                tmp_path = pl.Path(__file__).parent / f"_nvd_{year}.json"

                tmp_path.write_text(json.dumps(items), encoding="utf-8")


                from .db import load_bundled as _lb

                import aiosqlite

                async with aiosqlite.connect(db_path) as db:

                    for v in items:

                        await db.execute(

                            """INSERT OR IGNORE INTO vulnerabilities
                            (id,cve,title,description,severity,cvss,component,component_type,
                             affected_versions,fixed_version,vuln_references,remediation,updated_at)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",

                            (

                                v["id"], v["cve"], v["title"], v["description"],

                                v["severity"], v["cvss"], v["component"], v["component_type"],

                                json.dumps(v["affected_versions"]), v["fixed_version"],

                                json.dumps(v["references"]), v["remediation"], v["updated_at"],

                            ),

                        )

                        total_new += 1

                    await db.commit()

                tmp_path.unlink(missing_ok=True)



    return {"bundled": bundled_count, "nvd_new": total_new, "years": years}

