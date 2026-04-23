"""SQLite-backed cache for screening results."""
from __future__ import annotations

import json
import time

import aiosqlite

from .config import settings
from .models import CacheEntry, PillarResult, ScreenResponse, Verdict

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS screen_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package_key TEXT    NOT NULL UNIQUE,   -- "{name}@{version}"
    verdict     TEXT    NOT NULL,
    risk_score  REAL    NOT NULL,
    pillars_json TEXT   NOT NULL,
    created_at  REAL    NOT NULL,
    expires_at  REAL    NOT NULL
);
"""


def _pkg_key(name: str, version: str | None) -> str:
    return f"{name}@{version or 'latest'}"


async def init_db() -> None:
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        await db.execute(_CREATE_TABLE)
        await db.commit()


async def get_cached(name: str, version: str | None) -> ScreenResponse | None:
    key = _pkg_key(name, version)
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        async with db.execute(
            "SELECT verdict, risk_score, pillars_json FROM screen_cache "
            "WHERE package_key = ? AND expires_at > ?",
            (key, now),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    verdict, risk_score, pillars_json = row
    pillars = [PillarResult(**p) for p in json.loads(pillars_json)]
    return ScreenResponse(
        package_name=name,
        version=version,
        verdict=Verdict(verdict),
        risk_score=risk_score,
        pillars=pillars,
        cached=True,
    )


async def set_cached(response: ScreenResponse) -> None:
    key = _pkg_key(response.package_name, response.version)
    now = time.time()
    expires = now + settings.cache_ttl_seconds
    pillars_json = json.dumps([p.model_dump() for p in response.pillars])
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        await db.execute(
            """
            INSERT INTO screen_cache (package_key, verdict, risk_score, pillars_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(package_key) DO UPDATE SET
                verdict      = excluded.verdict,
                risk_score   = excluded.risk_score,
                pillars_json = excluded.pillars_json,
                created_at   = excluded.created_at,
                expires_at   = excluded.expires_at
            """,
            (key, response.verdict.value, response.risk_score, pillars_json, now, expires),
        )
        await db.commit()


async def purge_expired() -> int:
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        cursor = await db.execute("DELETE FROM screen_cache WHERE expires_at <= ?", (now,))
        await db.commit()
        return cursor.rowcount
