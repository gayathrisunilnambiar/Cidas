"""Sentinel pillar — registry reputation & AI hallucination detection.

When a package is ``ai_suggested`` the pillar runs a full hallucination-risk
check: does the package actually exist, how many downloads does it have, and
does its name suspiciously resemble a popular package?

When the package was typed by a human the hallucination check is skipped and
only basic typosquat detection is performed.

Steps
-----
1. If not ai_suggested → return low-risk PillarScore immediately.
2. ``check_registry_existence`` — download count, created date, repository.
3. ``check_name_similarity`` — edit distance against top-500 npm packages
   (bundled list).
4. ``compute_hallucination_risk`` — combine signals into a score.

TODO(phase-2): expand TOP_PACKAGES to a full top-500 list loaded from JSON.
TODO(phase-2): tune similarity thresholds based on false-positive data.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import PillarScore
from ..utils.logger import get_logger
from ..utils.npm_registry import get_download_count, get_package_metadata

log = get_logger(__name__)

# TODO(phase-2): replace with full top-500 list loaded from a bundled JSON file
TOP_PACKAGES: list[str] = [
    "react", "react-dom", "lodash", "express", "axios", "webpack", "babel-core",
    "typescript", "eslint", "prettier", "jest", "mocha", "chai", "chalk",
    "commander", "moment", "dayjs", "uuid", "dotenv", "cors", "body-parser",
    "mongoose", "sequelize", "socket.io", "next", "nuxt", "vue", "angular",
    "svelte", "tailwindcss", "postcss", "sass", "less", "nodemon", "ts-node",
    "cross-env", "rimraf", "concurrently", "husky", "lint-staged", "rollup",
    "vite", "esbuild", "turbopack", "jest-dom", "testing-library", "cypress",
    "playwright", "puppeteer", "cheerio", "got", "node-fetch", "undici",
]
_TYPO_THRESHOLD = 2


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


class Sentinel:
    """Pillar 2: detect AI hallucinations and typosquats via registry signals."""

    async def score(self, package_name: str, ai_suggested: bool) -> PillarScore:
        """Return a PillarScore; short-circuits for human-typed packages."""
        if not ai_suggested:
            is_typo, similar_to = self.check_name_similarity(package_name)
            if is_typo:
                return PillarScore(
                    score=40.0,
                    confidence=0.8,
                    flags=["typosquat_detected"],
                    metadata={"similar_to": similar_to, "ai_suggested": False},
                )
            return PillarScore(
                score=0.0,
                confidence=0.9,
                flags=[],
                metadata={"ai_suggested": False, "hallucination_check": "skipped"},
            )

        # Full hallucination-risk analysis for AI-suggested packages
        exists, registry_signals = await self.check_registry_existence(package_name)
        is_typo, similar_to = self.check_name_similarity(package_name)
        final_score, flags = self.compute_hallucination_risk(
            exists, registry_signals, is_typo, similar_to
        )

        return PillarScore(
            score=final_score,
            confidence=0.85,
            flags=flags,
            metadata={
                "ai_suggested": True,
                "exists": exists,
                "similar_to": similar_to,
                **registry_signals,
            },
        )

    async def check_registry_existence(self, package_name: str) -> tuple[bool, dict]:
        """Check NPM registry for package existence, age, and download count."""
        signals: dict = {}
        meta = await get_package_metadata(package_name)
        if meta is None:
            return False, {"registry_miss": True}

        # Age signal
        created_str = meta.get("time", {}).get("created", "")
        if created_str:
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
                signals["age_days"] = age_days
            except ValueError:
                signals["age_days"] = None

        # Download count signal
        try:
            downloads = await get_download_count(package_name)
            signals["monthly_downloads"] = downloads
        except Exception:
            signals["monthly_downloads"] = 0

        # Repository presence
        signals["has_repository"] = bool(meta.get("repository"))
        signals["maintainer_count"] = len(meta.get("maintainers", []))

        return True, signals

    def check_name_similarity(self, package_name: str) -> tuple[bool, str]:
        """Return (is_typosquat, similar_to) using edit distance against TOP_PACKAGES."""
        for popular in TOP_PACKAGES:
            dist = _levenshtein(package_name.lower(), popular.lower())
            if 0 < dist <= _TYPO_THRESHOLD:
                return True, popular
        return False, ""

    def compute_hallucination_risk(
        self,
        exists: bool,
        signals: dict,
        is_typo: bool,
        similar_to: str,
    ) -> tuple[float, list[str]]:
        """Combine registry signals into a risk score."""
        score = 0.0
        flags: list[str] = []

        if not exists:
            flags.append("package_not_found")
            score += 70.0
            if is_typo:
                flags.append("typosquat_detected")
                score += 15.0
            return min(score, 100.0), flags

        if is_typo:
            flags.append("typosquat_detected")
            score += 40.0

        age_days = signals.get("age_days")
        if isinstance(age_days, int):
            if age_days < 7:
                flags.append("very_new_package")
                score += 35.0
            elif age_days < 30:
                flags.append("new_package")
                score += 15.0

        monthly_dl = signals.get("monthly_downloads", 0)
        if monthly_dl == 0:
            flags.append("zero_downloads")
            score += 20.0
        elif monthly_dl < 100:
            flags.append("very_low_downloads")
            score += 10.0

        if not signals.get("has_repository"):
            flags.append("no_repository")
            score += 10.0

        return min(score, 100.0), flags
