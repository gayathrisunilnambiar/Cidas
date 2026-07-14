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

from ..config import get_admin_config
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

# ── Affix canonicalization ────────────────────────────────────────────────────
#
# Raw Levenshtein distance cannot catch affix squats ("node-react" is distance
# 5 from "react", far past any workable threshold) — this is a structurally
# separate signal: strip a known squat affix, then look for an *exact* match
# against TOP_PACKAGES. Affix hits still require reputation corroboration
# before escalating (see check_reputation_disparity) since some legitimate
# packages also carry these affixes (e.g. "node-sass" is a real, long-standing
# package, not a typosquat of "sass").
_AFFIX_PREFIXES: tuple[str, ...] = ("node-", "js-")
_AFFIX_SUFFIXES: tuple[str, ...] = ("-js", "-utils", "-util", "-helper", "-async", "-core", "-lib")

# ── Reputation-disparity thresholds ───────────────────────────────────────────
_REPUTATION_RATIO_THRESHOLD: float = 0.05  # candidate has <5% of target's downloads
_MATURE_AGE_DAYS: int = 365
_NEW_AGE_DAYS: int = 30


def _strip_affixes(name: str) -> str:
    """Strip one leading squat prefix and one trailing squat suffix (lowercased)."""
    n = name.lower()
    for p in _AFFIX_PREFIXES:
        if n.startswith(p) and len(n) > len(p):
            n = n[len(p):]
            break
    for s in _AFFIX_SUFFIXES:
        if n.endswith(s) and len(n) > len(s):
            n = n[: -len(s)]
            break
    return n


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

        admin_cfg = get_admin_config()
        affix_on = admin_cfg.get("typosquat_affix_canonicalization", True) is not False
        is_affix_typo, affix_similar_to = self.check_affix_similarity(package_name) if affix_on else (False, "")
        raw_hit = is_typo or is_affix_typo
        matched_target = similar_to or affix_similar_to

        # A raw-distance or affix name-similarity hit only escalates to a
        # forced BLOCK-level score once corroborated by a reputation
        # disparity vs. the matched target — otherwise short/legitimate
        # names collide by coincidence (e.g. "vue" vs "vite"). Disabling
        # typosquat_reputation_corroboration reverts to the pre-corroboration
        # behavior: any raw-distance hit forces score=100 unconditionally.
        corroboration_on = admin_cfg.get("typosquat_reputation_corroboration", True) is not False

        corroborated = False
        corr_info: dict = {}
        if raw_hit:
            if not corroboration_on:
                corroborated, corr_info = True, {"fallback": True}
            else:
                candidate_signals = registry_signals if exists else {"monthly_downloads": 0, "age_days": None}
                corroborated, corr_info = await self.check_reputation_disparity(
                    package_name, matched_target, candidate_signals,
                )

        # If package doesn't exist, always flag it regardless of ai_suggested
        if not exists:
            score = 85.0  # High risk for non-existent packages
            flags = ["package_not_found"]
            if is_affix_typo:
                flags.append("typosquat_affix_match")
            if raw_hit and corroborated:
                flags.append("typosquat_detected")
                if not corr_info.get("fallback"):
                    flags.append("reputation_disparity_confirmed")
                # A typosquat name that isn't even registered yet is at least as
                # dangerous as one that already exists (score=100 below) — the
                # attacker has staged the name but not yet published, or the
                # target simply doesn't exist. Never score this lower than an
                # existing typosquat.
                score = 100.0
            elif raw_hit:
                flags.append("typosquat_name_similarity_uncorroborated")
            return PillarScore(
                score=score,
                confidence=0.95,
                flags=flags,
                metadata={
                    "similar_to": similar_to, "affix_similar_to": affix_similar_to,
                    "ai_suggested": ai_suggested, "exists": False,
                    **{k: v for k, v in corr_info.items() if k != "fallback"},
                },
            )

        # Package exists - a corroborated typosquat hit forces the max score.
        if raw_hit and corroborated:
            flags = ["typosquat_detected"]
            if is_affix_typo:
                flags.append("typosquat_affix_match")
            if not corr_info.get("fallback"):
                flags.append("reputation_disparity_confirmed")
            return PillarScore(
                score=100.0,
                confidence=0.8,
                flags=flags,
                metadata={
                    "similar_to": similar_to, "affix_similar_to": affix_similar_to,
                    "ai_suggested": ai_suggested, "exists": True,
                    **{k: v for k, v in corr_info.items() if k != "fallback"},
                },
            )

        # A name-similarity hit that failed corroboration still surfaces as a
        # (non-forcing) flag through whichever scoring path runs below.
        uncorroborated_flags = ["typosquat_name_similarity_uncorroborated"] if raw_hit else []

        # For non-AI suggested packages that exist and aren't a corroborated typosquat, do basic checks
        if not ai_suggested:
            flags = list(uncorroborated_flags)
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
        flags = uncorroborated_flags + flags

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

    def check_affix_similarity(self, package_name: str) -> tuple[bool, str]:
        """Return (is_affix_typosquat, similar_to) — exact match against
        TOP_PACKAGES after stripping a known squat affix (e.g. "node-react"
        -> "react"). Distinct from check_name_similarity's raw edit-distance
        signal, since affix squats are often far past any workable
        Levenshtein threshold. Still requires reputation corroboration
        before escalating — some legitimate packages carry these affixes
        too (e.g. "node-sass").
        """
        canonical = _strip_affixes(package_name)
        if canonical == package_name.lower():
            return False, ""  # no affix was actually stripped
        for popular in TOP_PACKAGES:
            if canonical == popular.lower():
                return True, popular
        return False, ""

    async def check_reputation_disparity(
        self, candidate_name: str, target_name: str, candidate_signals: dict,
    ) -> tuple[bool, dict]:
        """Return (disparity_confirmed, info) for a name-similarity hit.

        A raw or affix name-similarity match alone isn't enough to force a
        BLOCK-level score — short/legitimate names collide by coincidence
        (e.g. "vue" vs "vite"). Disparity is confirmed when the candidate
        shows a large download-count gap vs. the matched target, or is very
        new while the target is long-established.

        Fails toward flagging, not suppression: if the target lookup itself
        fails (network error, confirmed-absent target), returns
        ``(True, {"fallback": True})`` so a corroboration-check outage never
        silently downgrades the pre-existing force-to-100 behavior.
        """
        try:
            target_meta, target_downloads = await asyncio.gather(
                get_package_metadata(target_name), get_download_count(target_name),
            )
        except Exception as exc:
            log.debug("reputation lookup failed for target %r (candidate %r): %s",
                      target_name, candidate_name, exc)
            return True, {"fallback": True}
        if target_meta is None:
            log.debug("target %r not found while corroborating candidate %r",
                      target_name, candidate_name)
            return True, {"fallback": True}

        candidate_downloads = candidate_signals.get("monthly_downloads", 0) or 0
        ratio = candidate_downloads / target_downloads if target_downloads > 0 else 0.0
        disparity_by_downloads = target_downloads > 0 and ratio < _REPUTATION_RATIO_THRESHOLD

        candidate_age = candidate_signals.get("age_days")
        target_created = target_meta.get("time", {}).get("created", "")
        target_age: int | None = None
        if target_created:
            try:
                target_age = (
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(target_created.replace("Z", "+00:00"))
                ).days
            except ValueError:
                target_age = None
        disparity_by_age = (
            isinstance(candidate_age, int) and candidate_age < _NEW_AGE_DAYS
            and isinstance(target_age, int) and target_age > _MATURE_AGE_DAYS
        )

        confirmed = disparity_by_downloads or disparity_by_age
        return confirmed, {
            "target_downloads": target_downloads,
            "download_ratio": round(ratio, 4),
            "target_age_days": target_age,
            "fallback": False,
        }

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
