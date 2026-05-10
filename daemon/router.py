"""FastAPI router — all HTTP endpoints for the CIDAS daemon.

Endpoints
---------
GET  /health                — liveness probe, no auth
POST /scan                  — screen an npm package (main entry point)
POST /trust                 — add a package to the local trust bypass list
GET  /trust/verify          — audit all trust-list HMACs (auth required)
DELETE /cache               — purge expired cache entries
POST /cache/invalidate      — emergency per-package cache invalidation (auth required)
GET  /audit                 — query structured scan audit log (auth required)
POST /audit/override        — record a user "Proceed Anyway" override event
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from .auth import get_or_create_token, require_token
from .config import get_settings
from .database import (
    TRUST_STATUS_LEGACY,
    TRUST_STATUS_TAMPERED,
    TRUST_STATUS_VERIFIED,
    add_trusted,
    check_trust,
    clear_expired,
    get_cached_result,
    invalidate_package,
    list_all_trusted,
    store_result,
)
from .models import HealthResponse, PackageScanRequest, PillarScore, ScanResponse
from .pillars.aggregator import Aggregator
from .pillars.contextify import Contextify
from .pillars.sentinel import Sentinel
from .pillars.shield import Shield
from .utils import audit_log
from .utils.logger import get_logger
from .utils.offline_cache import record_allow

log = get_logger(__name__)
router = APIRouter()

_contextify = Contextify()
_sentinel   = Sentinel()
_shield     = Shield()
_aggregator = Aggregator()


def _collect_signals(response: ScanResponse) -> list[str]:
    """Deduplicated list of all flags across all pillars + trust_flags."""
    seen: set[str] = set()
    out: list[str] = []
    for flag in (
        response.contextify.flags
        + response.sentinel.flags
        + response.shield.flags
        + response.trust_flags
    ):
        if flag not in seen:
            seen.add(flag)
            out.append(flag)
    return out


async def _audit_scan(
    req: PackageScanRequest,
    response: ScanResponse,
    *,
    cached: bool,
) -> None:
    """Append a structured scan record to the audit log (fire-and-forget)."""
    record = {
        "ts":           datetime.now(timezone.utc).isoformat(),
        "package":      f"{req.package_name}@{req.version or 'latest'}",
        "verdict":      response.decision,
        "score":        response.risk_score,
        "signals":      _collect_signals(response),
        "ai_suggested": req.ai_suggested,
        "project_path": req.project_path,
        "cached":       cached,
    }
    await audit_log.append(record)


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse()


@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(require_token)])
async def scan(req: PackageScanRequest) -> ScanResponse:
    """Screen an npm package; returns a cached result when available."""
    t0 = time.perf_counter()
    log.info("scan: %s@%s (ai_suggested=%s)", req.package_name, req.version or "latest", req.ai_suggested)

    # Trust bypass — check HMAC integrity before honoring the trust list.
    token = get_or_create_token()
    trust_result = await check_trust(req.package_name, token)

    if trust_result.status == TRUST_STATUS_VERIFIED:
        log.info("trust bypass (verified) for %s", req.package_name)
        trusted_score = PillarScore(score=0.0, confidence=1.0, flags=["trusted"], metadata={})
        await record_allow(req.package_name, req.version)
        response = ScanResponse(
            package_name=req.package_name,
            version=req.version,
            decision="ALLOW",
            risk_score=0.0,
            contextify=trusted_score,
            sentinel=trusted_score,
            shield=trusted_score,
            explanation=f"'{req.package_name}' is in the local trust list (HMAC verified).",
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
        await _audit_scan(req, response, cached=False)
        return response

    if trust_result.status == TRUST_STATUS_LEGACY:
        # Pre-MAC rows: trusted but unverified — return WARN so users know
        # re-adding via /trust will give them full integrity protection.
        log.warning("trust bypass (legacy, no MAC) for %s", req.package_name)
        legacy_score = PillarScore(
            score=0.0, confidence=0.5, flags=["trust_legacy_no_mac"], metadata={}
        )
        response = ScanResponse(
            package_name=req.package_name,
            version=req.version,
            decision="WARN",
            risk_score=40.0,
            contextify=legacy_score,
            sentinel=legacy_score,
            shield=legacy_score,
            explanation=(
                f"'{req.package_name}' is in the local trust list but was added before "
                "integrity protection was enabled. Re-add via POST /trust to upgrade."
            ),
            latency_ms=(time.perf_counter() - t0) * 1000,
            trust_flags=trust_result.flags,
        )
        await _audit_scan(req, response, cached=False)
        return response

    # TAMPERED: log.critical was emitted inside check_trust; fall through to
    # a full pillar scan and attach the flag so the VS Code panel can alert.
    tamper_flags = trust_result.flags if trust_result.status == TRUST_STATUS_TAMPERED else []

    # Cache lookup
    cached = await get_cached_result(req.package_name, req.version)
    if cached:
        log.debug("cache hit: %s", req.package_name)
        cached.latency_ms = (time.perf_counter() - t0) * 1000
        if tamper_flags:
            cached.trust_flags = tamper_flags
        await _audit_scan(req, cached, cached=True)
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
        trust_flags=tamper_flags,
    )

    await store_result(response)
    if decision == "ALLOW":
        # Mirror to offline-cache.json so the npm shim can serve known-good
        # packages silently when the daemon is unreachable.
        await record_allow(req.package_name, req.version)
    await _audit_scan(req, response, cached=False)
    log.info("result: decision=%s score=%.1f package=%s", decision, risk_score, req.package_name)
    return response


@router.post("/trust", dependencies=[Depends(require_token)])
async def trust(body: dict) -> dict:
    """Add a package to the local trust bypass list with an HMAC integrity tag."""
    package_name = body.get("package_name", "")
    if not package_name:
        raise HTTPException(status_code=422, detail="package_name is required")
    token = get_or_create_token()
    await add_trusted(package_name, token)
    log.info("trusted: %s", package_name)
    return {"trusted": package_name}


@router.get("/trust/verify", dependencies=[Depends(require_token)])
async def trust_verify() -> dict:
    """Audit every trust-list row and report HMAC verification results.

    Returns a summary count and the full list, including any rows that appear
    to have been tampered with directly in the SQLite file.
    Auth required so an attacker cannot probe which packages are trusted.
    """
    token = get_or_create_token()
    rows = await list_all_trusted(token)
    tampered = [r for r in rows if r["verification"] == TRUST_STATUS_TAMPERED]
    legacy   = [r for r in rows if r["verification"] == TRUST_STATUS_LEGACY]
    verified = len(rows) - len(tampered) - len(legacy)
    if tampered:
        log.critical(
            "trust/verify: %d tampered rows detected: %s",
            len(tampered),
            [r["package_name"] for r in tampered],
        )
    return {
        "total":            len(rows),
        "verified":         verified,
        "legacy_no_mac":    len(legacy),
        "tampered":         len(tampered),
        "tampered_packages": tampered,
        "entries":          rows,
    }


@router.delete("/cache", dependencies=[Depends(require_token)])
async def cache_delete() -> dict:
    """Purge all expired scan cache entries."""
    removed = await clear_expired()
    log.info("cache purge: removed %d expired entries", removed)
    return {"purged": removed}


@router.post("/cache/invalidate", dependencies=[Depends(require_token)])
async def cache_invalidate(body: dict) -> dict:
    """Emergency per-package cache invalidation.

    Body fields
    -----------
    package_name : str  — the npm package name (required)
    version      : str  — the specific version to evict, or ``"*"`` to evict
                          every cached version of the package (required)

    Returns ``{"invalidated": <count>}`` with the number of rows removed.
    A security team can call this immediately after a malicious-package
    disclosure to force a fresh scan on the next install attempt.
    """
    package_name = body.get("package_name", "")
    version = body.get("version", "")
    if not package_name:
        raise HTTPException(status_code=422, detail="package_name is required")
    if not version:
        raise HTTPException(
            status_code=422,
            detail='version is required; use "*" to invalidate all versions',
        )
    removed = await invalidate_package(package_name, version)
    log.info(
        "cache invalidate: package=%s version=%s removed=%d",
        package_name, version, removed,
    )
    return {"invalidated": removed, "package_name": package_name, "version": version}


@router.get("/audit", dependencies=[Depends(require_token)])
async def audit_query(
    last:    int            = Query(default=100, ge=1, le=1000, description="Maximum records to return"),
    verdict: Optional[str]  = Query(default=None, description="Filter by verdict: ALLOW, WARN, or BLOCK"),
    package: Optional[str]  = Query(default=None, description="Filter by package name (without version)"),
    since:   Optional[str]  = Query(default=None, description="Return only records newer than this ISO-8601 timestamp"),
) -> dict:
    """Return structured scan records from the audit log.

    Supports filtering by verdict, package name, and timestamp.  The newest
    matching records (up to *last*, max 1 000) are returned, oldest first.
    Auth required — the log contains project paths and package names.
    """
    if verdict and verdict not in ("ALLOW", "WARN", "BLOCK"):
        raise HTTPException(status_code=422, detail="verdict must be ALLOW, WARN, or BLOCK")
    events = await audit_log.read_records(last=last, verdict=verdict, package=package, since=since)
    log.debug("audit: returned %d records (filters: verdict=%s package=%s since=%s)", len(events), verdict, package, since)
    return {"events": events, "total": len(events)}


@router.post("/audit/override", dependencies=[Depends(require_token)])
async def audit_override(body: dict) -> dict:
    """Record a user 'Proceed Anyway' override event in the audit log.

    Called by the VS Code extension when the user proceeds past a WARN
    or BLOCK dialog.  The package name and version are required so the
    event can be correlated with the preceding scan record.

    Body fields
    -----------
    package_name : str            — npm package name (required)
    version      : str | null     — specific version, or null/absent for latest
    verdict_was  : str            — the verdict the user overrode (default "WARN")
    """
    package_name = body.get("package_name", "")
    if not package_name:
        raise HTTPException(status_code=422, detail="package_name is required")
    version     = body.get("version") or None
    verdict_was = body.get("verdict_was", "WARN")
    record = {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "event":       "user_override",
        "package":     f"{package_name}@{version or 'latest'}",
        "verdict_was": verdict_was,
    }
    await audit_log.append(record)
    log.info("audit: user_override for %s (verdict_was=%s)", record["package"], verdict_was)
    return {"logged": True, "package": record["package"]}
