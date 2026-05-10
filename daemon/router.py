"""FastAPI router — all HTTP endpoints for the CIDAS daemon.

Endpoints
---------
GET  /health   — liveness probe, no auth
POST /scan     — screen an npm package (main entry point)
POST /trust    — add a package to the local trust bypass list
DELETE /cache  — purge expired cache entries
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from .auth import require_token
from .config import get_settings
from .database import add_trusted, clear_expired, get_cached_result, is_trusted, store_result
from .models import HealthResponse, PackageScanRequest, PillarScore, ScanResponse
from .pillars.aggregator import Aggregator
from .pillars.contextify import Contextify
from .pillars.sentinel import Sentinel
from .pillars.shield import Shield
from .utils.logger import get_logger
from .utils.offline_cache import record_allow

log = get_logger(__name__)
router = APIRouter()

_contextify = Contextify()
_sentinel = Sentinel()
_shield = Shield()
_aggregator = Aggregator()


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse()


@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(require_token)])
async def scan(req: PackageScanRequest) -> ScanResponse:
    """Screen an npm package; returns a cached result when available."""
    t0 = time.perf_counter()
    log.info("scan: %s@%s (ai_suggested=%s)", req.package_name, req.version or "latest", req.ai_suggested)

    # Trust bypass
    if await is_trusted(req.package_name):
        log.info("trust bypass for %s", req.package_name)
        trusted_score = PillarScore(score=0.0, confidence=1.0, flags=["trusted"], metadata={})
        await record_allow(req.package_name)
        return ScanResponse(
            package_name=req.package_name,
            version=req.version,
            decision="ALLOW",
            risk_score=0.0,
            contextify=trusted_score,
            sentinel=trusted_score,
            shield=trusted_score,
            explanation=f"'{req.package_name}' is in the local trust list.",
            latency_ms=(time.perf_counter() - t0) * 1000,
        )

    # Cache lookup
    cached = await get_cached_result(req.package_name, req.version)
    if cached:
        log.debug("cache hit: %s", req.package_name)
        cached.latency_ms = (time.perf_counter() - t0) * 1000
        return cached

    # Run all three pillars concurrently
    ctx_score, sen_score, shi_score = await asyncio.gather(
        _contextify.score(req.package_name, req.project_path),
        _sentinel.score(req.package_name, req.ai_suggested),
        _shield.score(req.package_name, None),
    )

    settings = get_settings()
    risk_score, explanation = _aggregator.aggregate(ctx_score, sen_score, shi_score, settings)
    decision = _aggregator.get_decision(risk_score, settings)

    response = ScanResponse(
        package_name=req.package_name,
        version=req.version,
        decision=decision,  # type: ignore[arg-type]
        risk_score=risk_score,
        contextify=ctx_score,
        sentinel=sen_score,
        shield=shi_score,
        explanation=explanation,
        latency_ms=(time.perf_counter() - t0) * 1000,
        tarball_url=shi_score.metadata.get("tarball_url"),
        file_scan_summary=shi_score.metadata.get("file_scan_summary"),
    )

    await store_result(response)
    if decision == "ALLOW":
        # Mirror to offline-cache.json so the npm shim can serve known-good
        # packages silently when the daemon is unreachable.
        await record_allow(req.package_name)
    log.info("result: decision=%s score=%.1f package=%s", decision, risk_score, req.package_name)
    return response


@router.post("/trust", dependencies=[Depends(require_token)])
async def trust(body: dict) -> dict:
    """Add a package to the local trust bypass list."""
    package_name = body.get("package_name", "")
    if not package_name:
        raise HTTPException(status_code=422, detail="package_name is required")
    await add_trusted(package_name)
    log.info("trusted: %s", package_name)
    return {"trusted": package_name}


@router.delete("/cache", dependencies=[Depends(require_token)])
async def cache_delete() -> dict:
    """Purge all expired scan cache entries."""
    removed = await clear_expired()
    log.info("cache purge: removed %d expired entries", removed)
    return {"purged": removed}


@router.get("/audit")
async def audit_log() -> dict:
    """Return the last 100 bypass events from ~/.cidas/audit.log (read-only)."""
    audit_path = Path.home() / ".cidas" / "audit.log"

    def _read() -> list:
        try:
            lines = audit_path.read_text().splitlines()
        except FileNotFoundError:
            return []
        events = []
        for line in lines[-100:]:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                log.warning("audit: skipping malformed line: %.80s", line)
        return events

    events = await asyncio.to_thread(_read)
    log.debug("audit: returned %d bypass events", len(events))
    return {"events": events, "total": len(events)}
