"""Shield pillar — vulnerability & malicious-pattern detection.

Checks:
1. OSV database for known CVEs affecting the package/version
2. Heuristic patterns in package scripts (install hooks with network calls,
   obfuscated code, suspicious base64 blobs, environment variable exfiltration)
"""
from __future__ import annotations

import re

import httpx

from ..config import settings
from ..models import PillarResult, ScreenRequest
from ..utils.logger import get_logger
from ..utils.npm_registry import NpmRegistryClient

log = get_logger(__name__)

# Patterns that warrant heightened suspicion in lifecycle scripts
_MALICIOUS_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("network_in_install",   re.compile(r"\b(?:curl|wget|fetch|http\.get|axios\.get)\b"), 25),
    ("base64_decode",        re.compile(r"(?:Buffer\.from|atob|base64_decode)\s*\("), 20),
    ("eval_usage",           re.compile(r"\beval\s*\("),                                 30),
    ("env_exfil",            re.compile(r"process\.env\b.*(?:TOKEN|SECRET|KEY|PASS)",
                                         re.IGNORECASE),                                 35),
    ("dns_lookup",           re.compile(r"\bdns\.(?:lookup|resolve)\b"),                 15),
    ("child_process_exec",   re.compile(r"(?:exec|execSync|spawn)\s*\("),               15),
    ("crypto_miner_hint",    re.compile(r"(?:coinhive|cryptonight|stratum\+tcp)",
                                         re.IGNORECASE),                                 50),
]


async def _check_osv(package_name: str, version: str | None) -> tuple[float, list[str]]:
    query: dict = {"package": {"name": package_name, "ecosystem": "npm"}}
    if version:
        query["version"] = version

    try:
        async with httpx.AsyncClient(timeout=settings.osv_timeout) as client:
            resp = await client.post(f"{settings.osv_api_url}/query", json=query)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        log.warning("OSV query failed for %s: %s", package_name, exc)
        return 0.0, []

    vulns = data.get("vulns", [])
    ids = [v.get("id", "?") for v in vulns]

    # Score: each vuln adds weight; cap at 100
    score = min(len(vulns) * 25, 100)
    return float(score), ids


def _scan_scripts(scripts: dict[str, str]) -> tuple[float, dict]:
    lifecycle_hooks = {
        k: v for k, v in scripts.items()
        if k in ("preinstall", "install", "postinstall", "prepare")
    }
    if not lifecycle_hooks:
        return 0.0, {"lifecycle_hooks": False}

    signals: dict = {"lifecycle_hooks": True, "hook_names": list(lifecycle_hooks.keys()), "matches": []}
    total_score = 0.0

    combined_script = "\n".join(lifecycle_hooks.values())
    for label, pattern, weight in _MALICIOUS_PATTERNS:
        if pattern.search(combined_script):
            signals["matches"].append(label)
            total_score += weight

    return min(total_score, 100), signals


async def run(req: ScreenRequest) -> PillarResult:
    # 1. CVE lookup
    vuln_score, vuln_ids = await _check_osv(req.package_name, req.version)

    # 2. Fetch package.json scripts from registry tarball metadata
    script_score = 0.0
    script_signals: dict = {}
    async with NpmRegistryClient() as client:
        pkg_json = await client.fetch_package_json(req.package_name, req.version)

    if pkg_json:
        scripts = pkg_json.get("scripts", {})
        script_score, script_signals = _scan_scripts(scripts)

    combined_score = min(vuln_score * 0.6 + script_score * 0.4, 100)

    return PillarResult(
        pillar="shield",
        score=combined_score,
        signals={
            "vuln_ids": vuln_ids,
            "vuln_count": len(vuln_ids),
            "vuln_score": vuln_score,
            **script_signals,
        },
        notes=f"{len(vuln_ids)} known CVE(s). Script risk: {script_score:.1f}.",
    )
