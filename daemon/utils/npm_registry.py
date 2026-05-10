"""Async npm registry client.

All functions are module-level coroutines (not methods) so they can be
imported and mocked individually in tests without instantiating any class.

A 404 from the registry is treated as "package not found" and returns None,
which the calling pillar should treat as a high-risk signal.
"""
from __future__ import annotations

from typing import Any

import httpx

from ..config import get_settings
from .logger import get_logger

log = get_logger(__name__)

_TIMEOUT = httpx.Timeout(5.0)
_DOWNLOADS_BASE = "https://api.npmjs.org/downloads/point/last-month"


async def _get(url: str) -> dict[str, Any] | None:
    """Make a single GET request; returns parsed JSON or None on error."""
    for attempt in (1, 2):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(url, headers={"Accept": "application/json"})
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                return resp.json()  # type: ignore[return-value]
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            if attempt == 2:
                log.warning("GET %s failed after 2 attempts: %s", url, exc)
                return None
            log.debug("GET %s attempt %d failed, retrying: %s", url, attempt, exc)
        except httpx.HTTPStatusError as exc:
            log.warning("HTTP %s from %s", exc.response.status_code, url)
            return None
    return None  # unreachable, but satisfies mypy


async def get_package_metadata(name: str, version: str | None = None) -> dict[str, Any] | None:
    """Return full package metadata from the registry.

    If *version* is given, returns the version-specific package.json dict;
    otherwise returns the full registry document for *name*.
    """
    settings = get_settings()
    url = f"{settings.npm_registry_url}/{name}"
    meta = await _get(url)
    if meta is None:
        return None
    if version:
        return meta.get("versions", {}).get(version)
    return meta


async def get_download_count(name: str) -> int:
    """Return last-month download count from the npm downloads API."""
    data = await _get(f"{_DOWNLOADS_BASE}/{name}")
    if data is None:
        return 0
    return int(data.get("downloads", 0))


async def download_tarball(url: str, dest_path: str) -> bool:
    """Stream a tarball from *url* to *dest_path*. Returns True on success.

    Capped at 25 MiB to avoid pathological packages exhausting disk; npm's
    own per-tarball limit is well below this. Network failures return False
    so callers can degrade gracefully (skip the file scan).
    """
    max_bytes = 25 * 1024 * 1024
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), follow_redirects=True) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    log.warning("tarball GET %s returned HTTP %s", url, resp.status_code)
                    return False
                written = 0
                with open(dest_path, "wb") as f:
                    async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                        written += len(chunk)
                        if written > max_bytes:
                            log.warning("tarball %s exceeded %d-byte cap", url, max_bytes)
                            return False
                        f.write(chunk)
        return True
    except (httpx.TimeoutException, httpx.NetworkError, OSError) as exc:
        log.warning("tarball download failed for %s: %s", url, exc)
        return False


async def get_package_tarball_info(name: str, version: str | None) -> dict[str, Any] | None:
    """Return the dist/tarball metadata for a specific package version."""
    meta = await get_package_metadata(name)
    if meta is None:
        return None
    dist_tags: dict = meta.get("dist-tags", {})
    resolved_version = version or dist_tags.get("latest")
    if not resolved_version:
        return None
    versions: dict = meta.get("versions", {})
    pkg = versions.get(resolved_version)
    if pkg is None:
        return None
    return pkg.get("dist")
