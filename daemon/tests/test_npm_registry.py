"""Tests for daemon.utils.npm_registry.

HTTP calls are mocked at the httpx.AsyncClient level for _get / download_tarball,
and via patch on _get itself for the higher-level public functions.
asyncio_mode = "auto" is set in pyproject.toml so no @pytest.mark.asyncio needed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


# ── helpers ───────────────────────────────────────────────────────────────────

def _mock_client(status: int = 200, json_data: dict | None = None) -> MagicMock:
    """Return an async-context-manager mock for httpx.AsyncClient."""
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data or {}
    resp.raise_for_status = MagicMock()

    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _mock_client_raising(exc: Exception) -> MagicMock:
    """Return a mock client whose .get() raises *exc*."""
    client = MagicMock()
    client.get = AsyncMock(side_effect=exc)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


_SAMPLE_REGISTRY_META: dict = {
    "name": "lodash",
    "description": "Lodash modular utilities.",
    "dist-tags": {"latest": "4.17.21"},
    "time": {
        "created": "2012-04-20T00:00:00Z",
        "modified": "2022-01-01T00:00:00Z",
        "4.17.20": "2021-01-01T00:00:00Z",
        "4.17.21": "2021-10-01T00:00:00Z",
    },
    "maintainers": [{"name": "jdalton"}],
    "repository": {"url": "https://github.com/lodash/lodash"},
    "versions": {
        "4.17.20": {
            "name": "lodash",
            "version": "4.17.20",
            "dependencies": {"semver": "^7.0.0"},
            "dist": {"tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
        },
        "4.17.21": {
            "name": "lodash",
            "version": "4.17.21",
            "dependencies": {"semver": "^7.0.0"},
            "dist": {"tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
        },
    },
}


# ── _get — unit tests ─────────────────────────────────────────────────────────

async def test_get_returns_parsed_json_on_200() -> None:
    from daemon.utils.npm_registry import _get

    client = _mock_client(200, {"foo": "bar"})
    with patch("httpx.AsyncClient", return_value=client):
        result = await _get("https://example.com/pkg")

    assert result == {"foo": "bar"}


async def test_get_returns_none_on_404() -> None:
    from daemon.utils.npm_registry import _get

    client = _mock_client(404)
    with patch("httpx.AsyncClient", return_value=client):
        result = await _get("https://example.com/missing")

    assert result is None


async def test_get_returns_none_after_two_timeout_attempts() -> None:
    from daemon.utils.npm_registry import _get

    failing = _mock_client_raising(httpx.TimeoutException("timeout"))
    with patch("httpx.AsyncClient", return_value=failing):
        result = await _get("https://example.com/slow")

    assert result is None
    # Two attempts, each creates a new AsyncClient context
    assert failing.get.call_count == 2


async def test_get_retries_once_on_network_error_then_succeeds() -> None:
    from daemon.utils.npm_registry import _get

    failing = _mock_client_raising(httpx.NetworkError("reset"))
    success = _mock_client(200, {"ok": True})
    with patch("httpx.AsyncClient", side_effect=[failing, success]):
        result = await _get("https://example.com/flaky")

    assert result == {"ok": True}


async def test_get_returns_none_on_http_status_error() -> None:
    from daemon.utils.npm_registry import _get

    resp = MagicMock()
    resp.status_code = 500
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "500", request=MagicMock(), response=resp
    )
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=client):
        result = await _get("https://example.com/error")

    assert result is None


def test_timeout_constant_is_5_seconds() -> None:
    """The module-level _TIMEOUT must be a 5-second httpx.Timeout."""
    from daemon.utils import npm_registry

    assert isinstance(npm_registry._TIMEOUT, httpx.Timeout)
    assert npm_registry._TIMEOUT.read == 5.0


async def test_get_passes_timeout_to_async_client() -> None:
    from daemon.utils.npm_registry import _get, _TIMEOUT

    client = _mock_client(200, {})
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = client
        await _get("https://example.com/check")

    _, kwargs = mock_cls.call_args
    assert kwargs.get("timeout") is _TIMEOUT


# ── get_package_metadata ──────────────────────────────────────────────────────

async def test_get_package_metadata_success() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        result = await get_package_metadata("lodash")

    assert result is not None
    assert result["name"] == "lodash"
    assert "versions" in result


async def test_get_package_metadata_with_version_returns_version_dict() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        result = await get_package_metadata("lodash", version="4.17.21")

    assert result is not None
    assert result["version"] == "4.17.21"


async def test_get_package_metadata_unknown_version_returns_none() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        result = await get_package_metadata("lodash", version="0.0.0")

    assert result is None


async def test_get_package_metadata_404_returns_none() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=None)):
        result = await get_package_metadata("no-such-package-xyz")

    assert result is None


# ── get_download_count ────────────────────────────────────────────────────────

async def test_get_download_count_success() -> None:
    from daemon.utils.npm_registry import get_download_count

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value={"downloads": 50_000_000})):
        count = await get_download_count("lodash")

    assert count == 50_000_000


async def test_get_download_count_zero_on_404() -> None:
    from daemon.utils.npm_registry import get_download_count

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=None)):
        count = await get_download_count("no-such-pkg")

    assert count == 0


async def test_get_download_count_zero_when_field_missing() -> None:
    from daemon.utils.npm_registry import get_download_count

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value={"period": "last-month"})):
        count = await get_download_count("weird-pkg")

    assert count == 0


# ── get_direct_dependencies ───────────────────────────────────────────────────

async def test_get_direct_dependencies_exact_version() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        deps = await get_direct_dependencies("lodash", "4.17.21")

    assert deps == {"semver": "^7.0.0"}


async def test_get_direct_dependencies_falls_back_to_latest() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        deps = await get_direct_dependencies("lodash", None)

    assert deps == {"semver": "^7.0.0"}


async def test_get_direct_dependencies_range_version_resolves_to_latest() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        deps = await get_direct_dependencies("lodash", "^4.0.0")

    assert deps == {"semver": "^7.0.0"}


async def test_get_direct_dependencies_returns_empty_on_registry_miss() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=None)):
        deps = await get_direct_dependencies("ghost-pkg", "1.0.0")

    assert deps == {}


async def test_get_direct_dependencies_no_deps_field_returns_empty() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"name": "nodeps", "version": "1.0.0"}},
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=meta)):
        deps = await get_direct_dependencies("nodeps", "1.0.0")

    assert deps == {}


async def test_get_direct_dependencies_no_dist_tags_returns_empty() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    meta = {
        "dist-tags": {},
        "versions": {"1.0.0": {"dependencies": {"x": "1"}}},
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=meta)):
        deps = await get_direct_dependencies("bad-meta", "^1.0.0")

    assert deps == {}


# ── get_version_history ───────────────────────────────────────────────────────

async def test_get_version_history_returns_sorted_list() -> None:
    from daemon.utils.npm_registry import get_version_history

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        history = await get_version_history("lodash")

    assert len(history) == 2
    assert history[0]["version"] == "4.17.20"
    assert history[1]["version"] == "4.17.21"
    assert isinstance(history[0]["published"], datetime)


async def test_get_version_history_skips_created_modified_keys() -> None:
    from daemon.utils.npm_registry import get_version_history

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        history = await get_version_history("lodash")

    versions = [e["version"] for e in history]
    assert "created" not in versions
    assert "modified" not in versions


async def test_get_version_history_caps_at_max_history() -> None:
    from daemon.utils.npm_registry import get_version_history, _MAX_HISTORY

    many_versions = {str(i): {"name": "x", "version": str(i)} for i in range(20)}
    many_times = {str(i): f"2020-{i % 12 + 1:02d}-01T00:00:00Z" for i in range(20)}
    many_times["created"] = "2019-01-01T00:00:00Z"
    meta = {
        "dist-tags": {"latest": "19"},
        "versions": many_versions,
        "time": many_times,
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=meta)):
        history = await get_version_history("x")

    assert len(history) <= _MAX_HISTORY


async def test_get_version_history_returns_empty_on_registry_miss() -> None:
    from daemon.utils.npm_registry import get_version_history

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=None)):
        history = await get_version_history("ghost")

    assert history == []


async def test_get_version_history_skips_bad_timestamps() -> None:
    from daemon.utils.npm_registry import get_version_history

    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {}, "0.9.0": {}},
        "time": {
            "1.0.0": "2021-06-01T00:00:00Z",
            "0.9.0": "NOT-A-DATE",
        },
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=meta)):
        history = await get_version_history("partial")

    assert len(history) == 1
    assert history[0]["version"] == "1.0.0"


async def test_get_version_history_skips_orphaned_time_entries() -> None:
    """Versions in time dict but not in versions dict should be skipped."""
    from daemon.utils.npm_registry import get_version_history

    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {}},
        "time": {
            "1.0.0": "2021-01-01T00:00:00Z",
            "0.5.0": "2020-01-01T00:00:00Z",  # not in versions
        },
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=meta)):
        history = await get_version_history("orphan-test")

    assert len(history) == 1
    assert history[0]["version"] == "1.0.0"


# ── get_previous_version ──────────────────────────────────────────────────────

async def test_get_previous_version_returns_preceding_entry() -> None:
    from daemon.utils.npm_registry import get_previous_version

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        prev = await get_previous_version("lodash", "4.17.21")

    assert prev == "4.17.20"


async def test_get_previous_version_returns_none_for_first_version() -> None:
    from daemon.utils.npm_registry import get_previous_version

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        prev = await get_previous_version("lodash", "4.17.20")

    assert prev is None


async def test_get_previous_version_returns_none_for_missing_version() -> None:
    from daemon.utils.npm_registry import get_previous_version

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        prev = await get_previous_version("lodash", "9.9.9")

    assert prev is None


async def test_get_previous_version_returns_none_for_empty_string() -> None:
    from daemon.utils.npm_registry import get_previous_version

    prev = await get_previous_version("lodash", "")
    assert prev is None


async def test_get_previous_version_returns_none_on_registry_miss() -> None:
    from daemon.utils.npm_registry import get_previous_version

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=None)):
        prev = await get_previous_version("ghost", "1.0.0")

    assert prev is None


# ── get_package_tarball_info ──────────────────────────────────────────────────

async def test_get_package_tarball_info_success() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        info = await get_package_tarball_info("lodash", "4.17.21")

    assert info is not None
    assert "tarball" in info


async def test_get_package_tarball_info_uses_latest_when_no_version() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        info = await get_package_tarball_info("lodash", None)

    assert info is not None


async def test_get_package_tarball_info_returns_none_on_404() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=None)):
        info = await get_package_tarball_info("ghost", "1.0.0")

    assert info is None


async def test_get_package_tarball_info_returns_none_when_version_not_in_registry() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_SAMPLE_REGISTRY_META)):
        info = await get_package_tarball_info("lodash", "0.0.0")

    assert info is None


async def test_get_package_tarball_info_returns_none_when_no_dist_tags() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    meta = {
        "dist-tags": {},
        "versions": {},
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=meta)):
        info = await get_package_tarball_info("nodist", None)

    assert info is None


# ── download_tarball ──────────────────────────────────────────────────────────

def _streaming_client(status: int = 200, chunks: list[bytes] | None = None) -> MagicMock:
    """Return a mock AsyncClient that streams *chunks* as a response body."""
    chunks = chunks or [b"fake tarball data"]

    async def _aiter_bytes(chunk_size: int = 65536):
        for chunk in chunks:
            yield chunk

    mock_resp = MagicMock()
    mock_resp.status_code = status
    mock_resp.aiter_bytes = _aiter_bytes
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)

    mock_client = MagicMock()
    mock_client.stream = MagicMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


async def test_download_tarball_success_writes_file(tmp_path) -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = str(tmp_path / "pkg.tgz")
    with patch("httpx.AsyncClient", return_value=_streaming_client(200, [b"hello", b" world"])):
        ok = await download_tarball("https://example.com/pkg.tgz", dest)

    assert ok is True
    assert (tmp_path / "pkg.tgz").read_bytes() == b"hello world"


async def test_download_tarball_non_200_returns_false(tmp_path) -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = str(tmp_path / "pkg.tgz")
    with patch("httpx.AsyncClient", return_value=_streaming_client(404)):
        ok = await download_tarball("https://example.com/missing.tgz", dest)

    assert ok is False


async def test_download_tarball_timeout_returns_false(tmp_path) -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = str(tmp_path / "pkg.tgz")
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client):
        ok = await download_tarball("https://example.com/slow.tgz", dest)

    assert ok is False


async def test_download_tarball_exceeds_size_cap_returns_false(tmp_path) -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = str(tmp_path / "huge.tgz")
    huge_chunk = b"x" * (26 * 1024 * 1024)  # 26 MiB — over the 25 MiB cap
    with patch("httpx.AsyncClient", return_value=_streaming_client(200, [huge_chunk])):
        ok = await download_tarball("https://example.com/huge.tgz", dest)

    assert ok is False


async def test_download_tarball_uses_15_second_timeout() -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = "/dev/null"
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = _streaming_client()
        await download_tarball("https://example.com/pkg.tgz", dest)

    _, kwargs = mock_cls.call_args
    timeout = kwargs.get("timeout")
    assert timeout is not None
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.read == 15.0
