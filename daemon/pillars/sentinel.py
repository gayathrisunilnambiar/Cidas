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

import asyncio
from datetime import datetime, timezone

from ..models import PillarScore
from ..utils.logger import get_logger
from ..utils.npm_registry import get_download_count, get_package_metadata
from ..utils.osv_client import check_osv

log = get_logger(__name__)

# Packages with documented, public supply-chain compromise incidents.
# A hit here returns an immediate BLOCK-level score without further analysis.
# Only include packages where malware was *injected* (not just sabotaged or
# yanked) so the signal stays high-precision.
_KNOWN_COMPROMISED: dict[str, str] = {
    "flatmap-stream": "2018: backdoor via event-stream dependency (Bitcoin wallet theft)",
    "event-stream":   "2018: compromised via malicious flatmap-stream dependency",
    "node-ipc":       "2022: peacenotwar module (destructive file wipe on RU/BY IPs)",
    "ua-parser-js":   "2021: malware injection (cryptominer + password stealer)",
    "coa":            "2021: malware injection (cryptominer + password stealer)",
    "rc":             "2021: malware injection (cryptominer + password stealer)",
    "eslint-scope":   "2018: npm credentials theft via malicious postinstall",
}

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
        """Return a PillarScore; always checks registry existence."""
        # Known-incident blocklist: synchronous dict lookup, no network call.
        # Applies to all installs (human or AI-suggested) because historical
        # supply-chain attacks are equally dangerous regardless of install origin.
        if package_name in _KNOWN_COMPROMISED:
            return PillarScore(
                score=95.0,
                confidence=0.99,
                flags=["known_supply_chain_incident"],
                metadata={
                    "incident": _KNOWN_COMPROMISED[package_name],
                    "ai_suggested": ai_suggested,
                },
            )

        # Always check if package exists - this catches hallucinated/fake packages
        exists, registry_signals = await self.check_registry_existence(package_name)
        is_typo, similar_to = self.check_name_similarity(package_name)

        # If package doesn't exist, always flag it regardless of ai_suggested
        if not exists:
            score = 85.0  # High risk for non-existent packages
            flags = ["package_not_found"]
            if is_typo:
                flags.append("typosquat_detected")
                # A typosquat name that isn't even registered yet is at least as
                # dangerous as one that already exists (score=100 below) — the
                # attacker has staged the name but not yet published, or the
                # target simply doesn't exist. Never score this lower than an
                # existing typosquat.
                score = 100.0
            return PillarScore(
                score=score,
                confidence=0.95,
                flags=flags,
                metadata={"similar_to": similar_to, "ai_suggested": ai_suggested, "exists": False},
            )

        # Package exists - check for typosquats
        if is_typo:
            return PillarScore(
                score=100.0,
                confidence=0.8,
                flags=["typosquat_detected"],
                metadata={"similar_to": similar_to, "ai_suggested": ai_suggested, "exists": True},
            )

        # For non-AI suggested packages that exist and aren't typosquats, do basic checks
        if not ai_suggested:
            flags = []
            score = 0.0
            monthly_dl = registry_signals.get("monthly_downloads", 0)
            if monthly_dl == 0:
                flags.append("zero_downloads")
                score += 20.0
            elif monthly_dl < 100:
                flags.append("very_low_downloads")
                score += 10.0
            if not registry_signals.get("has_repository"):
                flags.append("no_repository")
                score += 10.0
            return PillarScore(
                score=score,
                confidence=0.9,
                flags=flags,
                metadata={"ai_suggested": False, "exists": True, "hallucination_check": "skipped", **registry_signals},
            )

        # Full hallucination-risk analysis for AI-suggested packages
        exists, registry_signals = await self.check_registry_existence(package_name)
        is_typo, similar_to = self.check_name_similarity(package_name)
        final_score, flags = self.compute_hallucination_risk(
            exists, registry_signals, is_typo, similar_to
        )

        # OSV vulnerability check — only for AI-suggested packages to avoid
        # adding a live network call to the human-typed fast path.
        osv = await check_osv(package_name)
        if osv["has_malware"]:
            # Confirmed malware (MAL- entry or unambiguous keyword) overrides all
            # other signals — the package is definitively dangerous.
            flags.append("osv_advisory_found")
            flags.append("osv_malware_confirmed")
            final_score = 100.0
        elif osv["vuln_count"] > 0:
            flags.append("osv_advisory_found")
            final_score = min(final_score + 20.0, 100.0)

        return PillarScore(
            score=final_score,
            confidence=0.85,
            flags=flags,
            metadata={
                "ai_suggested": True,
                "exists": exists,
                "similar_to": similar_to,
                "osv_vuln_count": osv["vuln_count"],
                "osv_vuln_ids": osv["vuln_ids"],
                **registry_signals,
            },
        )

    async def check_registry_existence(self, package_name: str) -> tuple[bool, dict]:
        """Check NPM registry for package existence, age, and download count."""
        signals: dict = {}
        meta = await get_package_metadata(package_name)
        if meta is None:
            # get_package_metadata returns None both for a confirmed 404 and
            # for an exhausted-retries network/transport failure — and this
            # is the one call site where treating a transient failure as
            # "confirmed absent" has a severe consequence (Sentinel forces a
            # BLOCK-level score for "package_not_found", regardless of
            # ai_suggested). One confirmatory re-fetch, after the failed
            # attempt's cache entry is evicted (see
            # npm_registry._fetch_registry_doc_cached), catches most
            # transient blips before we escalate to that.
            await asyncio.sleep(0.5)
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
