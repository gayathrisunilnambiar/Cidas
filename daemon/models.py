from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


# ── Request / Response ────────────────────────────────────────────────────────

class ScreenRequest(BaseModel):
    package_name: str = Field(..., description="npm package name")
    version: str | None = Field(None, description="Specific version; None = latest")
    project_root: str | None = Field(None, description="Absolute path to the project being installed into")
    install_args: list[str] = Field(default_factory=list, description="Raw npm install arguments")


class PillarResult(BaseModel):
    pillar: str
    score: float = Field(..., ge=0, le=100, description="Risk contribution 0–100")
    signals: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class ScreenResponse(BaseModel):
    package_name: str
    version: str | None
    verdict: Verdict
    risk_score: float = Field(..., ge=0, le=100)
    pillars: list[PillarResult]
    cached: bool = False
    message: str = ""


# ── Cache row ─────────────────────────────────────────────────────────────────

class CacheEntry(BaseModel):
    package_name: str
    version: str | None
    verdict: Verdict
    risk_score: float
    pillars_json: str
    created_at: float     # Unix timestamp
    expires_at: float


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
