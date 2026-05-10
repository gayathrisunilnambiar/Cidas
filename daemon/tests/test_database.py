"""Tests for daemon.database — SQLite cache and trust list operations."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import aiosqlite

from daemon.database import (
    _SCHEMA_VERSION,
    add_trusted,
    clear_expired,
    get_cached_result,
    init_db,
    invalidate_package,
    is_trusted,
    store_result,
)
from daemon.models import PillarScore, ScanResponse


def _ps(score: float = 0.0) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=[], metadata={})


def _make_response(
    name: str = "test-pkg",
    decision: str = "ALLOW",
    score: float = 10.0,
    version: str | None = None,
) -> ScanResponse:
    ps = _ps(score)
    return ScanResponse(
        package_name=name,
        version=version,
        decision=decision,  # type: ignore[arg-type]
        risk_score=score,
        contextify=ps,
        sentinel=ps,
        shield=ps,
        explanation="Test result.",
    )


@pytest.fixture
async def db(tmp_path):
    """Provide an isolated SQLite DB for each test; patch get_settings to point at it."""
    db_path = str(tmp_path / "test.db")
    mock_settings = MagicMock()
    mock_settings.sqlite_db_path = db_path
    with patch("daemon.database.get_settings", return_value=mock_settings):
        await init_db()
        yield db_path


# ── init_db ───────────────────────────────────────────────────────────────────

async def test_init_db_is_idempotent(tmp_path):
    """Calling init_db twice must not raise (CREATE TABLE IF NOT EXISTS)."""
    db_path = str(tmp_path / "idempotent.db")
    mock_settings = MagicMock()
    mock_settings.sqlite_db_path = db_path
    with patch("daemon.database.get_settings", return_value=mock_settings):
        await init_db()
        await init_db()


# ── store_result / get_cached_result ──────────────────────────────────────────

async def test_store_and_retrieve(db):
    """A stored ScanResponse must be returned intact by get_cached_result."""
    response = _make_response("lodash", "ALLOW", 5.0)
    await store_result(response)
    result = await get_cached_result("lodash", None)

    assert result is not None
    assert result.package_name == "lodash"
    assert result.decision == "ALLOW"
    assert result.risk_score == 5.0
    assert result.explanation == "Test result."


async def test_cache_miss_returns_none(db):
    result = await get_cached_result("nonexistent-pkg", None)
    assert result is None


async def test_version_keyed_separately(db):
    """Two versions of the same package must be cached as distinct entries."""
    await store_result(_make_response("axios", "ALLOW", 5.0, version="1.0.0"))
    await store_result(_make_response("axios", "WARN", 50.0, version="0.1.0"))

    r1 = await get_cached_result("axios", "1.0.0")
    r2 = await get_cached_result("axios", "0.1.0")

    assert r1 is not None and r1.risk_score == 5.0
    assert r2 is not None and r2.risk_score == 50.0


async def test_upsert_overwrites_existing(db):
    """Storing the same package twice must overwrite, not duplicate."""
    await store_result(_make_response("express", "ALLOW", 10.0))
    await store_result(_make_response("express", "WARN", 55.0))

    result = await get_cached_result("express", None)
    assert result is not None
    assert result.decision == "WARN"
    assert result.risk_score == 55.0


async def test_expired_entry_not_returned(db):
    """An entry with ttl_seconds=0 must be treated as already expired."""
    await store_result(_make_response("old-pkg"), ttl_seconds=0)
    result = await get_cached_result("old-pkg", None)
    assert result is None


# ── clear_expired ─────────────────────────────────────────────────────────────

async def test_clear_expired_removes_stale_entries(db):
    await store_result(_make_response("stale-pkg"), ttl_seconds=0)
    removed = await clear_expired()
    assert removed == 1


async def test_clear_expired_keeps_valid_entries(db):
    await store_result(_make_response("fresh-pkg"), ttl_seconds=3600)
    removed = await clear_expired()
    assert removed == 0


async def test_clear_expired_on_empty_db_returns_zero(db):
    removed = await clear_expired()
    assert removed == 0


async def test_clear_expired_only_removes_stale(db):
    """When both fresh and stale entries exist, only the stale one is removed."""
    await store_result(_make_response("stale-pkg"), ttl_seconds=0)
    await store_result(_make_response("fresh-pkg"), ttl_seconds=3600)
    removed = await clear_expired()
    assert removed == 1
    assert await get_cached_result("fresh-pkg", None) is not None


# ── add_trusted / is_trusted ──────────────────────────────────────────────────

async def test_add_trusted_and_is_trusted(db):
    await add_trusted("react")
    assert await is_trusted("react") is True


async def test_is_trusted_unknown_package(db):
    assert await is_trusted("not-trusted-pkg") is False


async def test_add_trusted_is_idempotent(db):
    """Adding the same package twice must not raise."""
    await add_trusted("lodash")
    await add_trusted("lodash")
    assert await is_trusted("lodash") is True


async def test_trust_does_not_bleed_between_packages(db):
    """Trusting one package must not affect unrelated packages."""
    await add_trusted("react")
    assert await is_trusted("lodash") is False


# ── invalidate_package ────────────────────────────────────────────────────────

async def test_invalidate_specific_version_removes_only_that_version(db):
    """Invalidating name@1.0.0 must leave name@2.0.0 untouched."""
    await store_result(_make_response("axios", "ALLOW", 5.0, version="1.0.0"))
    await store_result(_make_response("axios", "ALLOW", 5.0, version="2.0.0"))

    removed = await invalidate_package("axios", "1.0.0")

    assert removed == 1
    assert await get_cached_result("axios", "1.0.0") is None  # gone
    assert await get_cached_result("axios", "2.0.0") is not None  # still there


async def test_invalidate_wildcard_removes_all_versions(db):
    """version='*' must purge every cached version of a package."""
    await store_result(_make_response("lodash", "ALLOW", 5.0, version="4.17.20"))
    await store_result(_make_response("lodash", "ALLOW", 5.0, version="4.17.21"))
    await store_result(_make_response("react", "ALLOW", 3.0, version="18.0.0"))

    removed = await invalidate_package("lodash", "*")

    assert removed == 2
    assert await get_cached_result("lodash", "4.17.20") is None
    assert await get_cached_result("lodash", "4.17.21") is None
    assert await get_cached_result("react", "18.0.0") is not None  # different pkg


async def test_invalidate_wildcard_does_not_match_other_packages(db):
    """'lodash@*' must not evict 'lodash-cli@...' — prefix match is exact."""
    await store_result(_make_response("lodash", "ALLOW", 5.0, version="4.17.21"))
    await store_result(_make_response("lodash-cli", "ALLOW", 5.0, version="1.0.0"))

    removed = await invalidate_package("lodash", "*")

    assert removed == 1
    assert await get_cached_result("lodash-cli", "1.0.0") is not None


async def test_invalidate_nonexistent_returns_zero(db):
    removed = await invalidate_package("no-such-pkg", "1.0.0")
    assert removed == 0


async def test_different_versions_cached_independently(db):
    """This is the core regression test for the version-keyed cache: a safe
    1.0.0 and a malicious 1.0.1 must not share a cache entry."""
    await store_result(_make_response("evil-pkg", "ALLOW", 5.0, version="1.0.0"))
    await store_result(_make_response("evil-pkg", "BLOCK", 95.0, version="1.0.1"))

    r1 = await get_cached_result("evil-pkg", "1.0.0")
    r2 = await get_cached_result("evil-pkg", "1.0.1")

    assert r1 is not None and r1.decision == "ALLOW"
    assert r2 is not None and r2.decision == "BLOCK"


# ── Schema migration ──────────────────────────────────────────────────────────

async def test_schema_version_table_created_by_init_db(db):
    """init_db must create the schema_version table and record the current version."""
    async with aiosqlite.connect(db) as conn:
        async with conn.execute("SELECT MAX(version) FROM schema_version") as cur:
            row = await cur.fetchone()
    assert row is not None and row[0] == _SCHEMA_VERSION


async def test_migration_purges_pre_v2_rows(tmp_path):
    """Rows without '@' in package_key (written before v2) must be cleared on init."""
    db_path = str(tmp_path / "legacy.db")
    mock_settings = MagicMock()
    mock_settings.sqlite_db_path = db_path

    # Directly seed a legacy-format row into the DB before init_db sees it.
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("""
            CREATE TABLE scan_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_key TEXT NOT NULL UNIQUE,
                decision TEXT NOT NULL,
                risk_score REAL NOT NULL,
                context_json TEXT NOT NULL,
                sentinel_json TEXT NOT NULL,
                shield_json TEXT NOT NULL,
                explanation TEXT NOT NULL,
                scanned_at REAL NOT NULL,
                ttl_seconds INTEGER NOT NULL
            )
        """)
        await conn.execute(
            """INSERT INTO scan_cache
               (package_key, decision, risk_score, context_json, sentinel_json,
                shield_json, explanation, scanned_at, ttl_seconds)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            ("lodash", "ALLOW", 5.0, "{}", "{}", "{}", "old row", 0.0, 9999),
        )
        await conn.commit()

    with patch("daemon.database.get_settings", return_value=mock_settings):
        await init_db()
        # The legacy row (no "@") must be gone; a v2 row with "@" must survive.
        await store_result(_make_response("lodash", "ALLOW", 10.0, version="4.17.21"))
        result = await get_cached_result("lodash", "4.17.21")

    assert result is not None
    assert result.risk_score == 10.0

    async with aiosqlite.connect(db_path) as conn:
        async with conn.execute(
            "SELECT COUNT(*) FROM scan_cache WHERE package_key NOT LIKE '%@%'"
        ) as cur:
            row = await cur.fetchone()
    assert row[0] == 0  # all legacy rows purged
