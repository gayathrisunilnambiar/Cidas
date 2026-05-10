"""Pydantic models shared between the router, pillars, and database layers.

Keeping all external-facing request/response shapes in one module ensures
pillar implementations and the router stay in sync automatically.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


# ── Request ───────────────────────────────────────────────────────────────────

class PackageScanRequest(BaseModel):
    """Payload sent by the npm shim or VS Code extension to POST /scan."""

    package_name: str = Field(..., description="npm package name (no version suffix)")
    version: Optional[str] = Field(None, description="Specific version; None = latest")
    project_path: str = Field(..., description="Absolute path of the project root")
    ai_suggested: bool = Field(
        default=False,
        description="True when the package was suggested by an LLM/Copilot",
    )
    requesting_tool: Optional[str] = Field(
        None,
        description="Identifier of the calling tool, e.g. 'npm-shim' or 'vscode-extension'",
    )


# ── Pillar output ─────────────────────────────────────────────────────────────

class PillarScore(BaseModel):
    """Risk contribution from a single analysis pillar."""

    score: float = Field(..., ge=0.0, le=100.0, description="Risk 0–100 (higher = riskier)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the score")
    flags: list[str] = Field(default_factory=list, description="Human-readable signal labels")
    metadata: dict = Field(default_factory=dict, description="Raw signals for debugging")


# ── Scan response ─────────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    """Complete screening result returned to the caller."""

    package_name: str
    version: Optional[str]
    decision: Literal["ALLOW", "WARN", "BLOCK"]
    risk_score: float = Field(..., ge=0.0, le=100.0)
    contextify: PillarScore
    sentinel: PillarScore
    shield: PillarScore
    alternatives: list[str] = Field(default_factory=list, description="Safer package suggestions")
    explanation: str = Field(default="", description="Human-readable summary of the decision")
    latency_ms: float = Field(default=0.0, description="Total scan duration in milliseconds")
    tarball_url: Optional[str] = Field(
        default=None, description="The dist.tarball URL that Shield's file scan downloaded",
    )
    file_scan_summary: Optional[dict] = Field(
        default=None,
        description="Shield file-scan stats: files_scanned, flags, skipped (or None when no scan ran)",
    )
    trust_flags: list[str] = Field(
        default_factory=list,
        description=(
            "Trust-integrity signals: 'trust_tamper_detected' when a trust-list row HMAC "
            "mismatches, 'trust_legacy_no_mac' when the row predates integrity protection."
        ),
    )


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
