"""Aggregator pillar — combine pillar scores into a final verdict."""
from __future__ import annotations

import asyncio

from ..config import settings
from ..models import PillarResult, ScreenRequest, ScreenResponse, Verdict
from ..utils.logger import get_logger
from .contextify import run as contextify
from .sentinel import run as sentinel
from .shield import run as shield

log = get_logger(__name__)

# Pillar weights must sum to 1.0
_WEIGHTS: dict[str, float] = {
    "contextify": 0.15,
    "sentinel":   0.40,
    "shield":     0.45,
}


def _weighted_score(pillars: list[PillarResult]) -> float:
    total = 0.0
    for p in pillars:
        weight = _WEIGHTS.get(p.pillar, 0.0)
        total += p.score * weight
    return round(total, 2)


def _verdict(score: float) -> Verdict:
    if score >= settings.block_threshold:
        return Verdict.BLOCK
    if score >= settings.warn_threshold:
        return Verdict.WARN
    return Verdict.ALLOW


def _message(verdict: Verdict, score: float, name: str) -> str:
    if verdict == Verdict.BLOCK:
        return (
            f"CIDAS blocked installation of '{name}' (risk score {score:.0f}/100). "
            "One or more security checks failed. Review the signals before proceeding."
        )
    if verdict == Verdict.WARN:
        return (
            f"CIDAS flagged '{name}' with a moderate risk score ({score:.0f}/100). "
            "Proceed with caution and review the details."
        )
    return f"'{name}' passed all CIDAS checks (risk score {score:.0f}/100)."


async def aggregate(req: ScreenRequest) -> ScreenResponse:
    log.debug("aggregating pillars for %s@%s", req.package_name, req.version or "latest")

    pillar_results: list[PillarResult] = await asyncio.gather(
        contextify(req),
        sentinel(req),
        shield(req),
    )

    score = _weighted_score(pillar_results)
    verdict = _verdict(score)
    message = _message(verdict, score, req.package_name)

    log.info(
        "verdict=%s score=%.1f package=%s@%s",
        verdict.value, score, req.package_name, req.version or "latest",
    )

    return ScreenResponse(
        package_name=req.package_name,
        version=req.version,
        verdict=verdict,
        risk_score=score,
        pillars=pillar_results,
        cached=False,
        message=message,
    )
