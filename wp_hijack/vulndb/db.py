"""SQLite-backed vulnerability database with aiosqlite."""

from __future__ import annotations

import json

import pathlib

import asyncio

import aiosqlite

from typing import Any



_DEFAULT_DB = pathlib.Path(__file__).parent / "wp_hijack.db"

_BUNDLED_VULNS = pathlib.Path(__file__).parent / "vulns.json"



CREATE_SQL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          TEXT PRIMARY KEY,
    cve         TEXT,
    title       TEXT,
    description TEXT,
    severity    TEXT,
    cvss        REAL,
    component   TEXT,
    component_type TEXT,
    affected_versions TEXT,
    fixed_version TEXT,
    vuln_references  TEXT,
    remediation TEXT,
    updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve ON vulnerabilities(cve);
CREATE INDEX IF NOT EXISTS idx_component ON vulnerabilities(component);
"""





async def init_db(db_path: pathlib.Path = _DEFAULT_DB) -> None:

    async with aiosqlite.connect(db_path) as db:

        await db.executescript(CREATE_SQL)

        await db.commit()





async def load_bundled(db_path: pathlib.Path = _DEFAULT_DB) -> int:

    """Load/refresh bundled vulns.json into the database. Returns count inserted."""

    if not _BUNDLED_VULNS.exists():

        return 0

    data = json.loads(_BUNDLED_VULNS.read_text(encoding="utf-8"))

    vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])

    count = 0

    async with aiosqlite.connect(db_path) as db:

        for v in vulns:

            await db.execute(

                """
                INSERT OR REPLACE INTO vulnerabilities
                (id,cve,title,description,severity,cvss,component,component_type,
                 affected_versions,fixed_version,vuln_references,remediation,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,

                (

                    v.get("id", v.get("cve", "")),

                    v.get("cve"),

                    v.get("title"),

                    v.get("description"),

                    v.get("severity", "MEDIUM"),

                    float(v.get("cvss", 5.0)),

                    v.get("component"),

                    v.get("component_type", "plugin"),

                    json.dumps(v.get("affected_versions", [])),

                    v.get("fixed_version"),

                    json.dumps(v.get("references", [])),

                    v.get("remediation"),

                    v.get("updated_at", ""),

                ),

            )

            count += 1

        await db.commit()

    return count





async def query_by_component(

    component: str,

    db_path: pathlib.Path = _DEFAULT_DB,

) -> list[dict[str, Any]]:

    async with aiosqlite.connect(db_path) as db:

        db.row_factory = aiosqlite.Row

        cursor = await db.execute(

            "SELECT * FROM vulnerabilities WHERE component = ? COLLATE NOCASE",

            (component,),

        )

        rows = await cursor.fetchall()

        return [dict(r) for r in rows]





async def query_by_cve(cve: str, db_path: pathlib.Path = _DEFAULT_DB) -> dict | None:

    async with aiosqlite.connect(db_path) as db:

        db.row_factory = aiosqlite.Row

        cursor = await db.execute(

            "SELECT * FROM vulnerabilities WHERE cve = ? COLLATE NOCASE",

            (cve,),

        )

        row = await cursor.fetchone()

        return dict(row) if row else None





async def get_all(db_path: pathlib.Path = _DEFAULT_DB) -> list[dict[str, Any]]:

    async with aiosqlite.connect(db_path) as db:

        db.row_factory = aiosqlite.Row

        cur = await db.execute("SELECT * FROM vulnerabilities")

        rows = await cur.fetchall()

        return [dict(r) for r in rows]

