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

import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from ..config import get_admin_config
from ..models import PillarScore
from ..utils.logger import get_logger
from ..utils.npm_registry import download_tarball, get_package_metadata, get_package_tarball_info

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

# ── File-scan parameters ──────────────────────────────────────────────────────
#
# File-scan findings are weighted lower than lifecycle-script findings because:
#   1. Legitimate minified/bundled JS contains many of the same regex hits
#      (eval, Buffer.from, hex escapes) without being malicious.
#   2. Lifecycle scripts execute unconditionally on install, while a flagged
#      pattern in a .js file only runs if the package is actually required.
# 0.6 keeps the signal meaningful (a real malware payload still trips multiple
# patterns and clears the WARN threshold) while halving the false-positive
# weight on minified bundles.
FILE_SCAN_WEIGHT: float = 0.6
_FILE_SCAN_MAX_FILES: int = 50
_FILE_SCAN_MAX_BYTES: int = 200 * 1024  # 200 KB per file

# Require()-time patterns — checked in addition to _SCRIPT_PATTERNS for any
# .js file inside the tarball. These target code that runs at import time
# rather than at install time.
_DNS_REQUIRE_RE = re.compile(r"""require\s*\(\s*['"]dns['"]\s*\)""")
# Subdomain longer than 12 chars built from the alphabet attackers use for
# encoded payloads (lower/upper alnum). Excludes hyphens to skip benign
# hostnames like "long-but-readable-name.example.com".
_LONG_SUBDOMAIN_RE = re.compile(r"\b[A-Za-z0-9]{13,}\.[A-Za-z0-9.-]+\.[a-z]{2,}\b")
_PROCESS_ENV_RE   = re.compile(r"process\.env\.[A-Z_]{4,}")
_HTTP_FETCH_RE    = re.compile(r"\b(?:fetch|https?\.(?:get|request)|axios\.(?:get|post))\s*\(")
# Hex escape density — separate from the lifecycle-script "obfuscation" rule
# which fires only on contiguous runs. A file-wide >5 per 100 chars density
# catches payloads that interleave hex escapes with normal code.
_HEX_ESCAPE_RE    = re.compile(r"\\x[0-9a-fA-F]{2}")
_HEX_DENSITY_THRESHOLD: float = 5.0 / 100.0  # >5 hex escapes per 100 chars

# Per-finding scores for the require()-time pattern set. Tuned so that any
# single hit alone cannot push the file-scan total past ~30 (well below
# WARN), but two or three hits together cross the threshold.
_REQUIRE_TIME_SCORES: dict[str, float] = {
    "env_exfil_near_http":   30.0,
    "dns_long_subdomain":    35.0,
    "hex_density":           25.0,
}

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

        # File scan — downloads the tarball and statically inspects .js files.
        tarball_url = self._tarball_url_from_metadata(package_metadata)
        file_score, file_flags, file_summary = await self.scan_package_files(tarball_url)

        # TODO(phase-2): uncomment when secondary_verification LLM is available
        # secondary_score, secondary_flags = await self.secondary_verification(
        #     (script_score, script_flags), package_metadata
        # )

        combined = min(
            script_score * 0.7
            + injection_score * 0.3
            + file_score * FILE_SCAN_WEIGHT,
            100.0,
        )
        all_flags = script_flags + injection_flags + file_flags

        return PillarScore(
            score=combined,
            confidence=0.8,
            flags=all_flags,
            metadata={
                "script_score": script_score,
                "injection_score": injection_score,
                "file_score": file_score,
                "hooks_found": list(scripts.keys()),
                "tarball_url": tarball_url,
                "file_scan_summary": file_summary,
            },
        )

    @staticmethod
    def _tarball_url_from_metadata(metadata: dict) -> str | None:
        """Pull dist.tarball for the latest version out of registry metadata."""
        latest = (metadata.get("dist-tags") or {}).get("latest")
        versions = metadata.get("versions") or {}
        pkg = versions.get(latest) if latest else None
        if not pkg and versions:
            pkg = next(iter(versions.values()))
        dist = (pkg or {}).get("dist") or {}
        return dist.get("tarball") or None

    async def scan_package_files(
        self, tarball_url: str | None,
    ) -> tuple[float, list[str], dict]:
        """Download *tarball_url*, extract, and statically scan .js files.

        Returns ``(score, flags, summary)``. Score is the un-weighted total —
        the caller multiplies by ``FILE_SCAN_WEIGHT``. Summary is suitable
        for the VS Code "Show Details" panel: ``{"files_scanned", "flags",
        "skipped"}``.
        """
        admin_cfg = get_admin_config()
        # Default-on: only an explicit `false` disables file scanning.
        if admin_cfg.get("package_file_scan", True) is False:
            return 0.0, [], {"files_scanned": 0, "flags": 0, "skipped": "disabled_by_admin"}

        if not tarball_url:
            return 0.0, [], {"files_scanned": 0, "flags": 0, "skipped": "no_tarball_url"}

        tmp_dir = tempfile.mkdtemp(prefix="cidas-shield-")
        try:
            tar_path = os.path.join(tmp_dir, "package.tgz")
            ok = await download_tarball(tarball_url, tar_path)
            if not ok:
                return 0.0, [], {"files_scanned": 0, "flags": 0, "skipped": "download_failed"}

            extract_dir = os.path.join(tmp_dir, "unpacked")
            os.mkdir(extract_dir)
            try:
                self._safe_extract(tar_path, extract_dir)
            except (tarfile.TarError, OSError) as exc:
                log.warning("tarball extract failed: %s", exc)
                return 0.0, [], {"files_scanned": 0, "flags": 0, "skipped": "extract_failed"}

            score, flags, n = self._scan_extracted_dir(extract_dir)
            summary = {"files_scanned": n, "flags": len(flags), "skipped": None}
            return score, flags, summary
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _safe_extract(tar_path: str, dest: str) -> None:
        """Extract *tar_path* into *dest*, refusing path-traversal entries."""
        dest_abs = os.path.realpath(dest)
        with tarfile.open(tar_path, "r:*") as tf:
            for member in tf.getmembers():
                # Skip anything that's not a regular file or directory.
                if not (member.isfile() or member.isdir()):
                    continue
                target = os.path.realpath(os.path.join(dest, member.name))
                if not target.startswith(dest_abs + os.sep) and target != dest_abs:
                    raise tarfile.TarError(f"refusing path traversal entry: {member.name}")
            tf.extractall(dest)  # noqa: S202 — guarded above

    def _scan_extracted_dir(self, root: str) -> tuple[float, list[str], int]:
        """Walk *root*, scan up to _FILE_SCAN_MAX_FILES .js files."""
        total = 0.0
        # Use a set so a pattern hitting in three different files only adds
        # its weight once — otherwise legitimate vendored bundles dominate.
        seen: set[str] = set()
        scanned = 0
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if scanned >= _FILE_SCAN_MAX_FILES:
                    break
                if not name.endswith(".js"):
                    continue
                fpath = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(fpath) > _FILE_SCAN_MAX_BYTES:
                        continue
                    text = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                for label, score in self._scan_one_file(text):
                    if label not in seen:
                        seen.add(label)
                        total += score
                scanned += 1
            if scanned >= _FILE_SCAN_MAX_FILES:
                break

        return min(total, 100.0), sorted(seen), scanned

    @staticmethod
    def _scan_one_file(text: str) -> list[tuple[str, float]]:
        """Apply lifecycle patterns + require()-time patterns to *text*."""
        hits: list[tuple[str, float]] = []

        # 1. Reuse the lifecycle-script pattern table on the file body.
        for label, pattern, weight in _SCRIPT_PATTERNS:
            if pattern.search(text):
                hits.append((label, weight))

        # 2. process.env.<UPPER> within 5 lines of an http/https/fetch call.
        lines = text.splitlines()
        env_lines  = {i for i, ln in enumerate(lines) if _PROCESS_ENV_RE.search(ln)}
        http_lines = {i for i, ln in enumerate(lines) if _HTTP_FETCH_RE.search(ln)}
        if any(abs(e - h) <= 5 for e in env_lines for h in http_lines):
            hits.append(("env_exfil_near_http", _REQUIRE_TIME_SCORES["env_exfil_near_http"]))

        # 3. require('dns') near a domain string with a long random subdomain.
        if _DNS_REQUIRE_RE.search(text) and _LONG_SUBDOMAIN_RE.search(text):
            hits.append(("dns_long_subdomain", _REQUIRE_TIME_SCORES["dns_long_subdomain"]))

        # 4. High density of \x hex escapes (file-wide, not just contiguous).
        if text:
            density = len(_HEX_ESCAPE_RE.findall(text)) / max(len(text), 1)
            if density > _HEX_DENSITY_THRESHOLD:
                hits.append(("hex_density", _REQUIRE_TIME_SCORES["hex_density"]))

        return hits

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
