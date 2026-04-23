"""Async NPM registry client with rate limiting."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..config import settings
from .logger import get_logger

log = get_logger(__name__)


class NpmRegistryClient:
    """Async context manager wrapping httpx for NPM registry queries."""

    def __init__(self) -> None:
        self._sem = asyncio.Semaphore(settings.npm_max_concurrent)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "NpmRegistryClient":
        self._client = httpx.AsyncClient(
            base_url=settings.npm_registry_url,
            timeout=settings.npm_registry_timeout,
            headers={"Accept": "application/json"},
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_) -> None:
        if self._client:
            await self._client.aclose()

    async def _get(self, path: str) -> dict | None:
        assert self._client, "Use as async context manager"
        async with self._sem:
            try:
                resp = await self._client.get(path)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                log.warning("HTTP %s for %s", exc.response.status_code, path)
                return None
            except httpx.RequestError as exc:
                log.warning("Request error for %s: %s", path, exc)
                return None

    async def fetch_metadata(self, name: str) -> dict[str, Any] | None:
        """Fetch full package metadata (all versions)."""
        return await self._get(f"/{name}")

    async def fetch_package_json(self, name: str, version: str | None) -> dict[str, Any] | None:
        """Fetch the package.json for a specific (or latest) version."""
        meta = await self.fetch_metadata(name)
        if meta is None:
            return None
        if version:
            return meta.get("versions", {}).get(version)
        dist_tags = meta.get("dist-tags", {})
        latest = dist_tags.get("latest")
        if latest:
            return meta.get("versions", {}).get(latest)
        return None

    async def fetch_download_count(self, name: str, period: str = "last-week") -> int:
        """Query the NPM downloads API."""
        assert self._client
        try:
            resp = await self._client.get(
                f"https://api.npmjs.org/downloads/point/{period}/{name}"
            )
            resp.raise_for_status()
            return resp.json().get("downloads", 0)
        except Exception as exc:
            log.debug("Download count fetch failed for %s: %s", name, exc)
            return 0
