"""FastAPI router — all HTTP endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Header

from .config import settings
from .database import get_cached, set_cached
from .models import HealthResponse, ScreenRequest, ScreenResponse
from .pillars.aggregator import aggregate
from .utils.logger import get_logger

log = get_logger(__name__)
router = APIRouter()


def _verify_secret(x_cidas_secret: str | None = Header(default=None)) -> None:
    if settings.daemon_secret and x_cidas_secret != settings.daemon_secret:
        raise HTTPException(status_code=401, detail="Invalid or missing X-CIDAS-Secret header")


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse()


@router.post("/screen", response_model=ScreenResponse, dependencies=[Depends(_verify_secret)])
async def screen(req: ScreenRequest) -> ScreenResponse:
    log.info("screen request: %s@%s", req.package_name, req.version or "latest")

    cached = await get_cached(req.package_name, req.version)
    if cached:
        log.debug("cache hit for %s", req.package_name)
        return cached

    response = await aggregate(req)
    await set_cached(response)
    return response


@router.delete("/cache", dependencies=[Depends(_verify_secret)])
async def clear_cache() -> dict:
    from .database import purge_expired
    removed = await purge_expired()
    return {"purged": removed}
