"""Shield pillar — malicious-pattern detection and vulnerability scanning.

Steps
-----
1. ``fetch_install_scripts`` — retrieve lifecycle scripts from the npm
   registry tarball metadata.
2. ``primary_scan`` — pattern-based detection: obfuscation, network calls in
   install scripts, env variable exfiltration patterns.
3. ``secondary_verification`` — TODO: second LLM call for adversarial prompt
   injection detection in package description/README.
4. ``detect_injection_patterns`` — regex scan for known prompt injection phrases.

TODO(phase-2): integrate secondary_verification with a local LLM model for
adversarial README/description scanning.
TODO(phase-2): pull tarball and scan extracted JS for obfuscated payloads.
"""
from __future__ import annotations

import re

from ..models import PillarScore
from ..utils.logger import get_logger
from ..utils.npm_registry import get_package_metadata, get_package_tarball_info

log = get_logger(__name__)

# ── Lifecycle script patterns ─────────────────────────────────────────────────
_SCRIPT_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("network_in_install",  re.compile(r"\b(?:curl|wget|fetch|http\.get|axios\.get)\b"),   25.0),
    ("eval_usage",          re.compile(r"\beval\s*\("),                                      30.0),
    ("base64_decode",       re.compile(r"(?:Buffer\.from|atob|base64_decode)\s*\("),         20.0),
    ("env_exfil",           re.compile(r"process\.env\b.*(?:TOKEN|SECRET|KEY|PASS)",
                                        re.IGNORECASE),                                      35.0),
    ("child_process_exec",  re.compile(r"(?:exec|execSync|spawn)\s*\("),                     15.0),
    ("crypto_miner",        re.compile(r"(?:coinhive|cryptonight|stratum\+tcp)",
                                        re.IGNORECASE),                                      50.0),
    ("obfuscation",         re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?:0x[0-9a-fA-F]+,){5,}"), 30.0),
]

_LIFECYCLE_HOOKS = {"preinstall", "install", "postinstall", "prepare"}

# ── Prompt injection patterns in README/description ───────────────────────────
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore (?:previous|all prior) instructions", re.IGNORECASE),
    re.compile(r"disregard (?:your|the) (?:system|previous) (?:prompt|instructions)", re.IGNORECASE),
    re.compile(r"you are now (?:a|an|in)", re.IGNORECASE),
    re.compile(r"act as (?:a|an) (?:different|malicious)", re.IGNORECASE),
    re.compile(r"new persona[:\s]", re.IGNORECASE),
    re.compile(r"system:\s*you must", re.IGNORECASE),
]


class Shield:
    """Pillar 3: detect malicious scripts and prompt injection in package metadata."""

    async def score(self, package_name: str, package_metadata: dict | None) -> PillarScore:
        """Return a PillarScore for the candidate package."""
        if package_metadata is None:
            package_metadata = await get_package_metadata(package_name) or {}

        scripts = await self.fetch_install_scripts(package_name, package_metadata)
        readme = package_metadata.get("readme", "") or ""
        description = package_metadata.get("description", "") or ""

        script_score, script_flags = self.primary_scan(scripts, readme)

        # Injection detection in description and README
        injection_score, injection_flags = self._scan_injection(description + "\n" + readme)

        # TODO(phase-2): uncomment when secondary_verification LLM is available
        # secondary_score, secondary_flags = await self.secondary_verification(
        #     (script_score, script_flags), package_metadata
        # )

        combined = min(script_score * 0.7 + injection_score * 0.3, 100.0)
        all_flags = script_flags + injection_flags

        return PillarScore(
            score=combined,
            confidence=0.8,
            flags=all_flags,
            metadata={
                "script_score": script_score,
                "injection_score": injection_score,
                "hooks_found": list(scripts.keys()),
            },
        )

    async def fetch_install_scripts(self, package_name: str, metadata: dict) -> dict[str, str]:
        """Extract lifecycle scripts from the package metadata or tarball info."""
        # First try: scripts embedded in the registry metadata (dist-tags / latest version)
        dist_tags: dict = metadata.get("dist-tags", {})
        latest = dist_tags.get("latest")
        versions: dict = metadata.get("versions", {})

        pkg_json: dict = {}
        if latest and latest in versions:
            pkg_json = versions[latest]
        elif versions:
            pkg_json = next(iter(versions.values()))

        all_scripts: dict[str, str] = pkg_json.get("scripts", {})

        # TODO(phase-2): also fetch tarball and scan extracted install scripts
        return {k: v for k, v in all_scripts.items() if k in _LIFECYCLE_HOOKS}

    def primary_scan(self, scripts: dict[str, str], readme: str) -> tuple[float, list[str]]:
        """Run pattern-based scan over lifecycle scripts and README."""
        if not scripts:
            return 0.0, []

        combined = "\n".join(scripts.values())
        total = 0.0
        flags: list[str] = []
        for label, pattern, weight in _SCRIPT_PATTERNS:
            if pattern.search(combined):
                flags.append(label)
                total += weight

        return min(total, 100.0), flags

    async def secondary_verification(
        self,
        primary_result: tuple[float, list[str]],
        metadata: dict,
    ) -> tuple[float, list[str]]:
        """TODO(phase-2): call a local LLM to detect adversarial prompt injection.

        This method is reserved for a second-pass analysis using a small local
        language model that has been fine-tuned to detect prompt injection
        patterns in package metadata.  For now it returns a zero-risk score.
        """
        return 0.0, []

    def detect_injection_patterns(self, text: str) -> list[str]:
        """Return a list of matched injection pattern labels."""
        matched: list[str] = []
        for i, pattern in enumerate(_INJECTION_PATTERNS):
            if pattern.search(text):
                matched.append(f"injection_pattern_{i + 1}")
        return matched

    def _scan_injection(self, text: str) -> tuple[float, list[str]]:
        matched = self.detect_injection_patterns(text)
        score = min(len(matched) * 20.0, 60.0)
        return score, matched
