"""Offline-mode cache writer.

The daemon mirrors every ALLOW verdict into ``~/.cidas/offline-cache.json``
so that the npm shim can serve known-good packages without prompting the
developer when the daemon is unreachable.

File layout
-----------
A single JSON object keyed by package name::

    {
      "lodash": {
        "package_name": "lodash",
        "verdict":      "ALLOW",
        "timestamp":    "2026-05-10T12:00:00+00:00",
        "ttl_hours":    24
      },
      ...
    }

The shim treats an entry as valid while
``now() - timestamp < ttl_hours``.

Only ALLOW verdicts are written here. WARN/BLOCK never enter the offline
cache — if the daemon is down we want the user to *see* a missing verdict
for risky packages, not silently install them.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .logger import get_logger

log = get_logger(__name__)

DEFAULT_TTL_HOURS = 24
_CACHE_PATH = Path.home() / ".cidas" / "offline-cache.json"


def _path() -> Path:
    """Return the cache path; isolated as a function so tests can monkeypatch."""
    return _CACHE_PATH


def _read_sync(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        log.warning("offline-cache: ignoring malformed file %s: %s", path, exc)
        return {}


def _write_sync(path: Path, data: dict) -> None:
    """Atomic write — never leave a half-written JSON file behind."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".offline-cache.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


async def record_allow(package_name: str, ttl_hours: int = DEFAULT_TTL_HOURS) -> None:
    """Append/update an ALLOW entry in the offline cache.

    Failures are logged but never raised — a write error must not break the
    scan path. WARN / BLOCK results should not call this.
    """
    def _do() -> None:
        path = _path()
        cache = _read_sync(path)
        cache[package_name] = {
            "package_name": package_name,
            "verdict":      "ALLOW",
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "ttl_hours":    ttl_hours,
        }
        try:
            _write_sync(path, cache)
        except OSError as e:
            log.warning("offline-cache write failed for %s: %s", package_name, e)

    await asyncio.to_thread(_do)
