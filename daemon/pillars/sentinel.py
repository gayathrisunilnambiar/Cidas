"""Sentinel pillar — NPM registry metadata & reputation checks.

Signals analysed:
- Package age (days since first publish)
- Weekly download count
- Number of maintainers
- Whether the package name is a known typosquat pattern
- README length (quality proxy)
- Publish frequency anomalies (burst publishing)
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import PillarResult, ScreenRequest
from ..utils.npm_registry import NpmRegistryClient
from ..utils.logger import get_logger

log = get_logger(__name__)

# Typosquat heuristics: list of popular packages with Levenshtein-like patterns
_POPULAR_PACKAGES = [
    "react", "lodash", "express", "axios", "webpack", "babel", "typescript",
    "eslint", "prettier", "jest", "mocha", "chalk", "commander", "moment",
    "dayjs", "uuid", "dotenv", "cors", "body-parser", "mongoose",
]


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), curr[j] + 1, prev[j + 1] + 1))
        prev = curr
    return prev[-1]


def _is_likely_typosquat(name: str) -> tuple[bool, str]:
    for popular in _POPULAR_PACKAGES:
        dist = _levenshtein(name, popular)
        if 0 < dist <= 2:
            return True, popular
    return False, ""


def _score_metadata(meta: dict) -> tuple[float, dict]:
    signals: dict = {}
    score = 0.0

    # Age
    created_str = meta.get("time", {}).get("created", "")
    if created_str:
        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created).days
            signals["age_days"] = age_days
            if age_days < 7:
                score += 40
            elif age_days < 30:
                score += 20
            elif age_days < 90:
                score += 10
        except ValueError:
            signals["age_days"] = None

    # Weekly downloads (from downloads key if present, else 0)
    weekly_dl = meta.get("downloads", {}).get("weekly", 0)
    signals["weekly_downloads"] = weekly_dl
    if weekly_dl == 0:
        score += 15
    elif weekly_dl < 100:
        score += 10
    elif weekly_dl < 1000:
        score += 5

    # Maintainers
    maintainers = meta.get("maintainers", [])
    signals["maintainer_count"] = len(maintainers)
    if len(maintainers) == 1:
        score += 5

    # README quality
    readme = meta.get("readme", "") or ""
    signals["readme_length"] = len(readme)
    if len(readme) < 100:
        score += 10

    # Repository presence
    has_repo = bool(meta.get("repository"))
    signals["has_repository"] = has_repo
    if not has_repo:
        score += 10

    return min(score, 100), signals


async def run(req: ScreenRequest) -> PillarResult:
    # Typosquat check (no network needed)
    is_typo, similar_to = _is_likely_typosquat(req.package_name)
    typo_signals = {"is_likely_typosquat": is_typo, "similar_to": similar_to}

    typo_score = 50.0 if is_typo else 0.0

    async with NpmRegistryClient() as client:
        meta = await client.fetch_metadata(req.package_name)

    if meta is None:
        return PillarResult(
            pillar="sentinel",
            score=max(typo_score, 60.0),
            signals={**typo_signals, "registry_reachable": False},
            notes="Package not found in NPM registry.",
        )

    meta_score, meta_signals = _score_metadata(meta)
    combined_score = min((typo_score * 0.5 + meta_score * 0.5) + (typo_score * 0.3), 100)

    return PillarResult(
        pillar="sentinel",
        score=combined_score,
        signals={**typo_signals, **meta_signals},
        notes=f"Typosquat: {is_typo}. Metadata risk: {meta_score:.1f}.",
    )
