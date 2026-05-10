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
        patch("daemon.router.record_allow", new=AsyncMock()),
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


# ── Offline cache mirroring ──────────────────────────────────────────────────

async def test_allow_verdict_writes_offline_cache(async_client, mock_db, mock_pillars_low):
    """An ALLOW verdict must mirror to the offline cache for shim use."""
    with patch("daemon.router.record_allow", new=AsyncMock()) as rec_mock:
        await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    rec_mock.assert_called_once_with("lodash")


async def test_warn_verdict_does_NOT_write_offline_cache(async_client, mock_db):
    """WARN must not enter the offline cache — silent install would be unsafe."""
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=_ps(60.0))),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(40.0))),
        patch("daemon.router.record_allow",      new=AsyncMock()) as rec_mock,
    ):
        await async_client.post("/api/v1/scan", json={
            "package_name": "suspicious-pkg", "project_path": "/tmp/project",
        })
    rec_mock.assert_not_called()


async def test_block_verdict_does_NOT_write_offline_cache(async_client, mock_db):
    """BLOCK must not enter the offline cache."""
    high = _ps(100.0, flags=["package_not_found"])
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=high)),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=high)),
        patch("daemon.router.record_allow",      new=AsyncMock()) as rec_mock,
    ):
        await async_client.post("/api/v1/scan", json={
            "package_name": "evil-pkg", "project_path": "/tmp/project",
            "ai_suggested": True,
        })
    rec_mock.assert_not_called()


async def test_trust_bypass_writes_offline_cache(async_client, mock_db):
    """A trusted ALLOW must also persist to the offline cache."""
    with (
        patch("daemon.router.is_trusted", new=AsyncMock(return_value=True)),
        patch("daemon.router.record_allow", new=AsyncMock()) as rec_mock,
    ):
        await async_client.post("/api/v1/scan", json={
            "package_name": "internal-lib", "project_path": "/tmp/project",
        })
    rec_mock.assert_called_once_with("internal-lib")


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


# ── GET /audit ────────────────────────────────────────────────────────────────

async def test_audit_returns_empty_when_log_absent(async_client, tmp_path):
    """Endpoint returns empty list when audit.log does not exist."""
    with patch("daemon.router.Path") as mock_path_cls:
        mock_path_cls.home.return_value = tmp_path
        mock_path_cls.return_value = tmp_path / ".cidas" / "audit.log"
        # Use a real non-existent path
        import pathlib
        with patch("daemon.router.Path", new=pathlib.Path):
            fake_home = tmp_path  # audit.log doesn't exist under tmp_path
            with patch.object(pathlib.Path, "home", return_value=fake_home):
                response = await async_client.get("/api/v1/audit")
    assert response.status_code == 200
    body = response.json()
    assert body["events"] == []
    assert body["total"] == 0


async def test_audit_returns_parsed_events(async_client, tmp_path):
    """Endpoint parses newline-delimited JSON lines from audit.log."""
    import json as _json
    import pathlib

    cidas_dir = tmp_path / ".cidas"
    cidas_dir.mkdir()
    audit_log = cidas_dir / "audit.log"
    events = [
        {"timestamp": "2026-05-10T10:00:00Z", "package_names": ["lodash"],
         "bypass_reason": "env_var", "user": "alice", "cwd": "/project"},
        {"timestamp": "2026-05-10T10:05:00Z", "package_names": ["react", "axios"],
         "bypass_reason": "env_var", "user": "bob", "cwd": "/other"},
    ]
    audit_log.write_text("\n".join(_json.dumps(e) for e in events) + "\n")

    with patch.object(pathlib.Path, "home", return_value=tmp_path):
        response = await async_client.get("/api/v1/audit")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["events"][0]["user"] == "alice"
    assert body["events"][1]["package_names"] == ["react", "axios"]


async def test_audit_returns_at_most_100_events(async_client, tmp_path):
    """Endpoint caps results at 100 even when audit.log has more entries."""
    import json as _json
    import pathlib

    cidas_dir = tmp_path / ".cidas"
    cidas_dir.mkdir()
    audit_log = cidas_dir / "audit.log"
    lines = [
        _json.dumps({"timestamp": f"2026-05-10T{i:05d}Z", "package_names": ["pkg"],
                     "bypass_reason": "env_var", "user": "u", "cwd": "/"})
        for i in range(150)
    ]
    audit_log.write_text("\n".join(lines) + "\n")

    with patch.object(pathlib.Path, "home", return_value=tmp_path):
        response = await async_client.get("/api/v1/audit")

    body = response.json()
    assert body["total"] == 100  # capped at last 100


async def test_audit_skips_malformed_lines(async_client, tmp_path):
    """Malformed lines in audit.log are silently skipped."""
    import json as _json
    import pathlib

    cidas_dir = tmp_path / ".cidas"
    cidas_dir.mkdir()
    audit_log = cidas_dir / "audit.log"
    audit_log.write_text(
        _json.dumps({"timestamp": "2026-05-10T00:00:00Z", "package_names": ["lodash"],
                     "bypass_reason": "env_var", "user": "u", "cwd": "/"}) + "\n"
        "this is not json\n"
        "\n"  # empty line
        + _json.dumps({"timestamp": "2026-05-10T00:01:00Z", "package_names": ["react"],
                       "bypass_reason": "env_var", "user": "u", "cwd": "/"}) + "\n"
    )

    with patch.object(pathlib.Path, "home", return_value=tmp_path):
        response = await async_client.get("/api/v1/audit")

    body = response.json()
    assert body["total"] == 2  # malformed line and empty line skipped
