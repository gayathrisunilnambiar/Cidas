"""Integration tests for the FastAPI router endpoints.

Uses the async_client fixture (httpx ASGITransport) — no real network or SQLite I/O.
Pillar scores and database operations are mocked to keep tests fast and deterministic.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from daemon.database import TrustCheckResult, TRUST_STATUS_UNKNOWN, TRUST_STATUS_VERIFIED
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


_UNKNOWN_TRUST = TrustCheckResult(status=TRUST_STATUS_UNKNOWN, package_name="")
_VERIFIED_TRUST = TrustCheckResult(status=TRUST_STATUS_VERIFIED, package_name="")


@pytest.fixture
def mock_db():
    """Patch all database references in daemon.router to avoid SQLite I/O."""
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result", new=AsyncMock()),
        patch("daemon.router.add_trusted", new=AsyncMock()),
        patch("daemon.router.clear_expired", new=AsyncMock(return_value=3)),
        patch("daemon.router.invalidate_package", new=AsyncMock(return_value=1)),
        patch("daemon.router.list_all_trusted", new=AsyncMock(return_value=[])),
        patch("daemon.router.record_allow", new=AsyncMock()),
        patch("daemon.router.audit_log.append", new=AsyncMock()),
        patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=[])),
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
    # 0.30×0 + 0.35×80 + 0.35×40 = 0 + 28 + 14 = 42 → WARN
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=_ps(80.0))),
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
    # ctx=100 + sentinel=100 + shield=100 → 100 → BLOCK.
    high = _ps(100.0, flags=["package_not_found", "eval_usage"])
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(100.0))),
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
    """A VERIFIED trusted package must return ALLOW immediately without calling pillars."""
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=_VERIFIED_TRUST)),
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
    rec_mock.assert_called_once_with("lodash", None)


async def test_warn_verdict_does_NOT_write_offline_cache(async_client, mock_db):
    """WARN must not enter the offline cache — silent install would be unsafe."""
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=_ps(80.0))),
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
    """A verified-trusted ALLOW must also persist to the offline cache."""
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=_VERIFIED_TRUST)),
        patch("daemon.router.record_allow", new=AsyncMock()) as rec_mock,
    ):
        await async_client.post("/api/v1/scan", json={
            "package_name": "internal-lib", "project_path": "/tmp/project",
        })
    rec_mock.assert_called_once_with("internal-lib", None)


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

async def test_audit_returns_empty_when_log_absent(async_client):
    """Endpoint returns empty list when no records match."""
    with patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=[])):
        response = await async_client.get("/api/v1/audit")
    assert response.status_code == 200
    body = response.json()
    assert body["events"] == []
    assert body["total"] == 0


async def test_audit_returns_parsed_events(async_client):
    """Endpoint returns records from audit_log.read_records."""
    events = [
        {"ts": "2026-05-10T10:00:00+00:00", "package": "lodash@4", "verdict": "ALLOW",
         "score": 5.0, "signals": [], "ai_suggested": False, "project_path": "/p", "cached": False},
        {"ts": "2026-05-10T10:05:00+00:00", "package": "axios@1", "verdict": "WARN",
         "score": 45.0, "signals": [], "ai_suggested": False, "project_path": "/p", "cached": False},
    ]
    with patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=events)):
        response = await async_client.get("/api/v1/audit")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["events"][0]["package"] == "lodash@4"
    assert body["events"][1]["verdict"] == "WARN"


async def test_audit_passes_query_params_to_read_records(async_client):
    """Query parameters are forwarded to audit_log.read_records correctly."""
    with patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=[])) as mock_rr:
        await async_client.get("/api/v1/audit?verdict=BLOCK&package=lodash&last=50")
    mock_rr.assert_awaited_once_with(last=50, verdict="BLOCK", package="lodash", since=None)


async def test_audit_invalid_verdict_returns_422(async_client):
    """An unrecognised verdict value must be rejected with 422."""
    response = await async_client.get("/api/v1/audit?verdict=MAYBE")
    assert response.status_code == 422


# ── POST /cache/invalidate ────────────────────────────────────────────────────

async def test_cache_invalidate_specific_version(async_client, mock_db):
    """Invalidating a specific version removes exactly that entry."""
    with patch("daemon.router.invalidate_package", new=AsyncMock(return_value=1)) as inv_mock:
        response = await async_client.post(
            "/api/v1/cache/invalidate",
            json={"package_name": "lodash", "version": "4.17.21"},
            headers={"Authorization": "Bearer ignored-in-test"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["invalidated"] == 1
    assert body["package_name"] == "lodash"
    assert body["version"] == "4.17.21"
    inv_mock.assert_called_once_with("lodash", "4.17.21")


async def test_cache_invalidate_wildcard_all_versions(async_client, mock_db):
    """version='*' must be forwarded verbatim to invalidate_package."""
    with patch("daemon.router.invalidate_package", new=AsyncMock(return_value=3)) as inv_mock:
        response = await async_client.post(
            "/api/v1/cache/invalidate",
            json={"package_name": "lodash", "version": "*"},
        )
    assert response.status_code == 200
    assert response.json()["invalidated"] == 3
    inv_mock.assert_called_once_with("lodash", "*")


async def test_cache_invalidate_missing_package_name_returns_422(async_client, mock_db):
    response = await async_client.post(
        "/api/v1/cache/invalidate", json={"version": "1.0.0"}
    )
    assert response.status_code == 422


async def test_cache_invalidate_missing_version_returns_422(async_client, mock_db):
    response = await async_client.post(
        "/api/v1/cache/invalidate", json={"package_name": "lodash"}
    )
    assert response.status_code == 422


# ── Version propagation in scan ───────────────────────────────────────────────

async def test_scan_with_explicit_version_mirrors_to_offline_cache(
    async_client, mock_db, mock_pillars_low
):
    """An ALLOW for name@version must record the version in the offline-cache call."""
    with patch("daemon.router.record_allow", new=AsyncMock()) as rec_mock:
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "version": "4.17.21",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    rec_mock.assert_called_once_with("lodash", "4.17.21")


# ── Trust integrity — router behavior ─────────────────────────────────────────

async def test_legacy_trust_returns_warn(async_client, mock_db):
    """A legacy trust row (no MAC) must return WARN and not skip the scan."""
    from daemon.database import TrustCheckResult, TRUST_STATUS_LEGACY
    legacy = TrustCheckResult(
        status=TRUST_STATUS_LEGACY, package_name="old-pkg", flags=["trust_legacy_no_mac"]
    )
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=legacy)),
        patch("daemon.router._contextify.score", new=AsyncMock()) as ctx,
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "old-pkg", "project_path": "/tmp",
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "WARN"
    assert "trust_legacy_no_mac" in body["trust_flags"]
    # Legacy trust still short-circuits the pillar scan.
    ctx.assert_not_called()


async def test_tampered_trust_runs_full_scan_with_flag(async_client, mock_db, mock_pillars_low):
    """A tampered trust row must NOT short-circuit; the flag appears in the response."""
    from daemon.database import TrustCheckResult, TRUST_STATUS_TAMPERED
    tampered = TrustCheckResult(
        status=TRUST_STATUS_TAMPERED,
        package_name="tampered-pkg",
        flags=["trust_tamper_detected"],
    )
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=tampered)),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))) as ctx,
        patch("daemon.router._sentinel.score",  new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._shield.score",    new=AsyncMock(return_value=_ps(0.0))),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "tampered-pkg", "project_path": "/tmp",
        })
    assert response.status_code == 200
    body = response.json()
    assert "trust_tamper_detected" in body["trust_flags"]
    ctx.assert_called_once()  # full pillar scan ran


# ── GET /trust/verify ─────────────────────────────────────────────────────────

async def test_trust_verify_empty_list(async_client, mock_db):
    """Verify endpoint returns empty report when no packages are trusted."""
    with patch("daemon.router.list_all_trusted", new=AsyncMock(return_value=[])):
        response = await async_client.get("/api/v1/trust/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 0
    assert body["tampered"] == 0
    assert body["tampered_packages"] == []


async def test_trust_verify_reports_tampered_rows(async_client, mock_db):
    """Verify endpoint must surface tampered rows in tampered_packages."""
    from daemon.database import TRUST_STATUS_TAMPERED, TRUST_STATUS_VERIFIED
    fake_rows = [
        {"package_name": "react",  "added_at": 1.0, "source": "api",
         "mac_status": "ok", "verification": TRUST_STATUS_VERIFIED},
        {"package_name": "evil",   "added_at": 2.0, "source": "api",
         "mac_status": "ok", "verification": TRUST_STATUS_TAMPERED},
    ]
    with patch("daemon.router.list_all_trusted", new=AsyncMock(return_value=fake_rows)):
        response = await async_client.get("/api/v1/trust/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["verified"] == 1
    assert body["tampered"] == 1
    assert body["tampered_packages"][0]["package_name"] == "evil"


async def test_trust_verify_reports_legacy_rows(async_client, mock_db):
    """Verify endpoint must count legacy rows separately from tampered ones."""
    from daemon.database import TRUST_STATUS_LEGACY, TRUST_STATUS_VERIFIED
    fake_rows = [
        {"package_name": "old-pkg", "added_at": 1.0, "source": "api",
         "mac_status": "legacy_no_mac", "verification": TRUST_STATUS_LEGACY},
        {"package_name": "new-pkg", "added_at": 2.0, "source": "api",
         "mac_status": "ok", "verification": TRUST_STATUS_VERIFIED},
    ]
    with patch("daemon.router.list_all_trusted", new=AsyncMock(return_value=fake_rows)):
        response = await async_client.get("/api/v1/trust/verify")
    body = response.json()
    assert body["legacy_no_mac"] == 1
    assert body["tampered"] == 0
    assert body["verified"] == 1
