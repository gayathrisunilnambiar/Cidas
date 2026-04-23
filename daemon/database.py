"""Async SQLite cache for scan results.

The ``scan_cache`` table stores completed ScanResponse objects keyed by
``package_name@version``.  Each row carries a ``ttl_seconds`` field; entries
are considered valid as long as ``scanned_at + ttl_seconds > now()``.

Call ``init_db()`` once at daemon startup before any reads or writes.
"""
from __future__ import annotations

import json
import time

import aiosqlite

from .config import get_settings
from .models import PillarScore, ScanResponse
from .utils.logger import get_logger

log = get_logger(__name__)

_DEFAULT_TTL = 3600  # 1 hour

_CREATE_SCAN_CACHE = """
CREATE TABLE IF NOT EXISTS scan_cache (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_key  TEXT    NOT NULL UNIQUE,
    decision     TEXT    NOT NULL,
    risk_score   REAL    NOT NULL,
    context_json TEXT    NOT NULL,
    sentinel_json TEXT   NOT NULL,
    shield_json  TEXT    NOT NULL,
    explanation  TEXT    NOT NULL,
    scanned_at   REAL    NOT NULL,
    ttl_seconds  INTEGER NOT NULL
);
"""

_CREATE_TRUST_CACHE = """
CREATE TABLE IF NOT EXISTS trust_cache (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT    NOT NULL UNIQUE,
    added_at     REAL    NOT NULL
);
"""


def _pkg_key(name: str, version: str | None) -> str:
    return f"{name}@{version or 'latest'}"


async def init_db() -> None:
    """Create tables if they do not exist."""
    settings = get_settings()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        await db.execute(_CREATE_SCAN_CACHE)
        await db.execute(_CREATE_TRUST_CACHE)
        await db.commit()
    log.info("SQLite cache initialised at %s", settings.sqlite_db_path)


async def get_cached_result(name: str, version: str | None) -> ScanResponse | None:
    """Return a cached ScanResponse or None if missing/expired."""
    settings = get_settings()
    key = _pkg_key(name, version)
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        async with db.execute(
            """
            SELECT decision, risk_score, context_json, sentinel_json, shield_json,
                   explanation, scanned_at, ttl_seconds
            FROM scan_cache
            WHERE package_key = ? AND (scanned_at + ttl_seconds) > ?
            """,
            (key, now),
        ) as cursor:
            row = await cursor.fetchone()

    if row is None:
        return None

    decision, risk_score, ctx_j, sen_j, shi_j, explanation, _, _ = row
    return ScanResponse(
        package_name=name,
        version=version,
        decision=decision,  # type: ignore[arg-type]
        risk_score=risk_score,
        contextify=PillarScore(**json.loads(ctx_j)),
        sentinel=PillarScore(**json.loads(sen_j)),
        shield=PillarScore(**json.loads(shi_j)),
        explanation=explanation,
    )


async def store_result(response: ScanResponse, ttl_seconds: int = _DEFAULT_TTL) -> None:
    """Persist a ScanResponse; upserts on conflict."""
    settings = get_settings()
    key = _pkg_key(response.package_name, response.version)
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        await db.execute(
            """
            INSERT INTO scan_cache
                (package_key, decision, risk_score, context_json, sentinel_json,
                 shield_json, explanation, scanned_at, ttl_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(package_key) DO UPDATE SET
                decision      = excluded.decision,
                risk_score    = excluded.risk_score,
                context_json  = excluded.context_json,
                sentinel_json = excluded.sentinel_json,
                shield_json   = excluded.shield_json,
                explanation   = excluded.explanation,
                scanned_at    = excluded.scanned_at,
                ttl_seconds   = excluded.ttl_seconds
            """,
            (
                key,
                response.decision,
                response.risk_score,
                json.dumps(response.contextify.model_dump()),
                json.dumps(response.sentinel.model_dump()),
                json.dumps(response.shield.model_dump()),
                response.explanation,
                now,
                ttl_seconds,
            ),
        )
        await db.commit()


async def clear_expired() -> int:
    """Delete expired rows; returns the count removed."""
    settings = get_settings()
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        cursor = await db.execute(
            "DELETE FROM scan_cache WHERE (scanned_at + ttl_seconds) <= ?", (now,)
        )
        await db.commit()
        return cursor.rowcount


async def add_trusted(package_name: str) -> None:
    """Mark a package as locally trusted (skips future screening)."""
    settings = get_settings()
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        await db.execute(
            """
            INSERT INTO trust_cache (package_name, added_at) VALUES (?, ?)
            ON CONFLICT(package_name) DO UPDATE SET added_at = excluded.added_at
            """,
            (package_name, now),
        )
        await db.commit()


async def is_trusted(package_name: str) -> bool:
    """Return True if the package is in the local trust cache."""
    settings = get_settings()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        async with db.execute(
            "SELECT 1 FROM trust_cache WHERE package_name = ?", (package_name,)
        ) as cursor:
            return await cursor.fetchone() is not None
