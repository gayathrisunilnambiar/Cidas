"""Async npm registry client.

All functions are module-level coroutines (not methods) so they can be
imported and mocked individually in tests without instantiating any class.

A 404 from the registry is treated as "package not found" and returns None,
which the calling pillar should treat as a high-risk signal.
"""
from __future__ import annotations

import re
from datetime import datetime
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


_EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+")


async def get_direct_dependencies(name: str, version: str | None) -> dict[str, str]:
    """Return the direct dependencies declared in name@version's package manifest.

    *version* may be an exact semver (``"1.2.3"``) or a semver range
    (``"^1.0.0"``).  Ranges and ``None`` are resolved to the package's current
    ``dist-tags.latest`` version.  Returns an empty dict on any error so callers
    can degrade gracefully without special-casing failures.
    """
    meta = await get_package_metadata(name)
    if meta is None:
        return {}
    dist_tags: dict = meta.get("dist-tags", {})
    versions: dict = meta.get("versions", {})

    # Use the requested version only when it's an exact semver present in the registry.
    cleaned = (version or "").lstrip("v=")
    if _EXACT_VERSION_RE.match(cleaned) and cleaned in versions:
        resolved = cleaned
    else:
        resolved = dist_tags.get("latest") or ""
    if not resolved or resolved not in versions:
        return {}

    manifest = versions[resolved]
    return dict(manifest.get("dependencies", {}) or {})


# Maximum number of recent versions returned by get_version_history.
# Cap exists because some packages have hundreds of versions (e.g. react),
# and diff analysis only ever needs the immediately-preceding entry.
_MAX_HISTORY = 10


async def get_version_history(name: str) -> list[dict[str, Any]]:
    """Return ``[{"version": str, "published": datetime}]`` oldest-first.

    Reads ``meta["time"]`` from the registry document and pairs each version
    string with its publish timestamp. Capped at the **10 most recent**
    versions to keep diff analysis bounded. Returns ``[]`` on registry miss
    or when no parseable timestamps are present.
    """
    meta = await get_package_metadata(name)
    if meta is None:
        return []

    times: dict = meta.get("time", {}) or {}
    versions: dict = meta.get("versions", {}) or {}

    history: list[dict[str, Any]] = []
    for version, published_str in times.items():
        # 'created'/'modified' are document-level meta-keys, not real versions.
        if version in ("created", "modified"):
            continue
        # Skip orphaned timestamps that don't correspond to a real version.
        if version not in versions:
            continue
        try:
            published = datetime.fromisoformat(str(published_str).replace("Z", "+00:00"))
        except (ValueError, AttributeError, TypeError):
            continue
        history.append({"version": version, "published": published})

    history.sort(key=lambda d: d["published"])
    return history[-_MAX_HISTORY:]


async def get_previous_version(name: str, current_version: str) -> str | None:
    """Return the version published immediately before *current_version*.

    Returns ``None`` if *current_version* is the first release in the bounded
    history window, isn't present in the registry, or the registry is
    unreachable.
    """
    if not current_version:
        return None
    history = await get_version_history(name)
    for i, entry in enumerate(history):
        if entry["version"] == current_version:
            return history[i - 1]["version"] if i > 0 else None
    return None


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
