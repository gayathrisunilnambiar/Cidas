"""Integration tests for the FastAPI router endpoints.

Uses the async_client fixture (httpx ASGITransport) — no real network or SQLite I/O.
Pillar scores and database operations are mocked to keep tests fast and deterministic.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from daemon.models import PillarScore, ScanResponse


def _ps(score: float = 0.0, flags: list[str] | None = None) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=flags or [], metadata={})


def _cached_response(name: str = "cached-pkg", decision: str = "ALLOW") -> ScanResponse:
    ps = _ps(0.0)
    return ScanResponse(
        package_name=name,
        version=None,
        decision=decision,  # type: ignore[arg-type]
        risk_score=0.0,
        contextify=ps,
        sentinel=ps,
        shield=ps,
        explanation="Cached result.",
    )


@pytest.fixture
def mock_db():
    """Patch all database references in daemon.router to avoid SQLite I/O."""
    with (
        patch("daemon.router.is_trusted", new=AsyncMock(return_value=False)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result", new=AsyncMock()),
        patch("daemon.router.add_trusted", new=AsyncMock()),
        patch("daemon.router.clear_expired", new=AsyncMock(return_value=3)),
    ):
        yield


@pytest.fixture
def mock_pillars_low():
    """Patch all three pillar score() methods to return zero risk."""
    low = _ps(0.0)
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=low)),
    ):
        yield


# ── GET /health ───────────────────────────────────────────────────────────────

async def test_health_returns_ok(async_client):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


# ── POST /scan — decision paths ───────────────────────────────────────────────

async def test_scan_allow(async_client, mock_db, mock_pillars_low):
    """All-zero pillar scores must produce ALLOW with risk_score == 0."""
    response = await async_client.post("/api/v1/scan", json={
        "package_name": "lodash",
        "project_path": "/tmp/project",
        "ai_suggested": False,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert body["risk_score"] == 0.0
    assert body["package_name"] == "lodash"
    assert "latency_ms" in body


async def test_scan_warn(async_client, mock_db):
    """Pillar scores that land in the WARN band (40–79) must produce WARN."""
    # sentinel=60 → 0.40×60=24; shield=40 → 0.45×40=18; total=42 → WARN
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=_ps(60.0))),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=_ps(40.0))),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "suspicious-pkg",
            "project_path": "/tmp/project",
            "ai_suggested": True,
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "WARN"
    assert 40.0 <= body["risk_score"] < 80.0


async def test_scan_block(async_client, mock_db):
    """High pillar scores must produce BLOCK with risk_score >= 80."""
    # sentinel=100 + shield=100 → 0.40×100+0.45×100=85 → BLOCK
    high = _ps(100.0, flags=["package_not_found", "eval_usage"])
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=high)),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=high)),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "malicious-pkg",
            "project_path": "/tmp/project",
            "ai_suggested": True,
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["risk_score"] >= 80.0


# ── POST /scan — cache and trust paths ────────────────────────────────────────

async def test_scan_cache_hit_skips_pillars(async_client, mock_db):
    """A cache hit must return immediately without invoking any pillar."""
    cached = _cached_response("lodash", "ALLOW")
    with (
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=cached)),
        patch("daemon.router._contextify.score", new=AsyncMock()) as ctx,
        patch("daemon.router._sentinel.score", new=AsyncMock()) as sen,
        patch("daemon.router._shield.score", new=AsyncMock()) as shi,
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    ctx.assert_not_called()
    sen.assert_not_called()
    shi.assert_not_called()


async def test_scan_trust_bypass_skips_pillars(async_client, mock_db):
    """A trusted package must return ALLOW immediately without calling pillars."""
    with (
        patch("daemon.router.is_trusted", new=AsyncMock(return_value=True)),
        patch("daemon.router._contextify.score", new=AsyncMock()) as ctx,
        patch("daemon.router._sentinel.score", new=AsyncMock()) as sen,
        patch("daemon.router._shield.score", new=AsyncMock()) as shi,
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "react",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert body["risk_score"] == 0.0
    ctx.assert_not_called()
    sen.assert_not_called()
    shi.assert_not_called()


async def test_scan_response_includes_pillar_breakdown(async_client, mock_db, mock_pillars_low):
    """ScanResponse must expose contextify, sentinel, and shield sub-objects."""
    response = await async_client.post("/api/v1/scan", json={
        "package_name": "lodash",
        "project_path": "/tmp/project",
    })
    assert response.status_code == 200
    body = response.json()
    for pillar in ("contextify", "sentinel", "shield"):
        assert pillar in body
        assert "score" in body[pillar]
        assert "flags" in body[pillar]


async def test_scan_result_is_stored(async_client, mock_db, mock_pillars_low):
    """After a full scan (cache miss), store_result must be called once."""
    with patch("daemon.router.store_result", new=AsyncMock()) as store_mock:
        await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    store_mock.assert_called_once()


# ── POST /trust ───────────────────────────────────────────────────────────────

async def test_trust_endpoint_returns_trusted_name(async_client, mock_db):
    response = await async_client.post("/api/v1/trust", json={"package_name": "lodash"})
    assert response.status_code == 200
    assert response.json()["trusted"] == "lodash"


async def test_trust_endpoint_missing_name_returns_422(async_client, mock_db):
    response = await async_client.post("/api/v1/trust", json={})
    assert response.status_code == 422


# ── DELETE /cache ─────────────────────────────────────────────────────────────

async def test_cache_delete_returns_purge_count(async_client, mock_db):
    response = await async_client.delete("/api/v1/cache")
    assert response.status_code == 200
    body = response.json()
    assert "purged" in body
    assert isinstance(body["purged"], int)
