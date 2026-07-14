"""Tests for the Sentinel pillar.

Covers the hallucination-risk path (ai_suggested=True) and the fast-path
(ai_suggested=False) separately.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from daemon.models import PillarScore
from daemon.pillars.sentinel import Sentinel, _levenshtein


@pytest.fixture
def sentinel() -> Sentinel:
    return Sentinel()


# ── Unit tests ────────────────────────────────────────────────────────────────

def test_typosquatted_name_detected(sentinel: Sentinel) -> None:
    """Names one edit away from a popular package must be flagged."""
    is_typo, similar_to = sentinel.check_name_similarity("lodahs")
    assert is_typo is True
    assert similar_to == "lodash"

    is_typo2, _ = sentinel.check_name_similarity("reakt")
    assert is_typo2 is True


def test_exact_name_not_flagged_as_typosquat(sentinel: Sentinel) -> None:
    """An exact match to a popular package should NOT be flagged as a typosquat."""
    is_typo, _ = sentinel.check_name_similarity("react")
    assert is_typo is False


# ── Integration tests (async with mocked network) ─────────────────────────────

_NO_OSV = {"vuln_count": 0, "has_malware": False, "vuln_ids": []}


@pytest.mark.asyncio
async def test_ai_suggested_nonexistent_package_scores_high(sentinel: Sentinel) -> None:
    """An AI-suggested package that does not exist in the registry should score high."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=None)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("totally-made-up-pkg-xyz123", ai_suggested=True)

    assert isinstance(result, PillarScore)
    assert result.score >= 60.0
    assert "package_not_found" in result.flags


@pytest.mark.asyncio
async def test_human_typed_package_skips_hallucination_check(sentinel: Sentinel) -> None:
    """Human-typed installs skip the *hallucination* risk analysis (age/OSV/etc.)

    Registry existence is still checked unconditionally regardless of
    ai_suggested (that's what catches fake/typosquatted names for human-typed
    installs too) — only compute_hallucination_risk and the OSV lookup are
    skipped. 'webpack' is an exact match in TOP_PACKAGES (distance == 0) so
    the typosquat check does not fire either, giving a clean score of 0.
    """
    good_meta = {
        "time": {"created": "2016-01-01T00:00:00Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}],
        "repository": {"url": "https://github.com/webpack/webpack"},
        "versions": {"5.0.0": {}},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=good_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock()) as mock_osv,
    ):
        result = await sentinel.score("webpack", ai_suggested=False)

    assert isinstance(result, PillarScore)
    assert result.score == 0.0
    assert result.metadata.get("hallucination_check") == "skipped"
    mock_osv.assert_not_called()


@pytest.mark.asyncio
async def test_real_package_scores_low(sentinel: Sentinel) -> None:
    """A well-established AI-suggested package with downloads should score low."""
    good_meta = {
        "time": {"created": "2016-01-01T00:00:00Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}],
        "repository": {"url": "https://github.com/lodash/lodash"},
        "versions": {"4.17.21": {}},
        "dist-tags": {"latest": "4.17.21"},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=good_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("lodash", ai_suggested=True)

    assert isinstance(result, PillarScore)
    assert result.score < 30.0


@pytest.mark.asyncio
async def test_new_ai_suggested_package_scores_higher(sentinel: Sentinel) -> None:
    """A brand-new package with zero downloads should receive a higher risk score."""
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_meta = {
        "time": {"created": recent},
        "maintainers": [{"name": "anon"}],
        "repository": None,
        "versions": {"0.0.1": {}},
        "dist-tags": {"latest": "0.0.1"},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=new_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("brand-new-package", ai_suggested=True)

    assert result.score >= 40.0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_meta(
    created: str = "2020-01-01T00:00:00Z",
    has_repo: bool = True,
    maintainers: int = 2,
) -> dict:
    meta: dict = {
        "time": {"created": created},
        "maintainers": [{"name": f"m{i}"} for i in range(maintainers)],
    }
    meta["repository"] = {"url": "https://github.com/example/pkg"} if has_repo else None
    return meta


# ── Non-AI suggested download / repository flags (lines 95-102) ──────────────

@pytest.mark.asyncio
async def test_zero_downloads_flag_set(sentinel: Sentinel) -> None:
    """Non-AI package with zero downloads sets zero_downloads flag and score > 0."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_make_meta())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert "zero_downloads" in result.flags
    assert result.score > 0.0


@pytest.mark.asyncio
async def test_very_low_downloads_flag_set(sentinel: Sentinel) -> None:
    """Non-AI package with 50 downloads (< 100) sets very_low_downloads flag."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_make_meta())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=50)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert "very_low_downloads" in result.flags
    assert "zero_downloads" not in result.flags


@pytest.mark.asyncio
async def test_no_repository_flag_set(sentinel: Sentinel) -> None:
    """Non-AI package with no repository field sets no_repository flag."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_make_meta(has_repo=False))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=1000)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert "no_repository" in result.flags


# ── Existing typosquat path (lines 81-87) ─────────────────────────────────────

@pytest.mark.asyncio
async def test_existing_typosquat_scores_100(sentinel: Sentinel) -> None:
    """Package that exists and is a typosquat (dist=1 from 'lodash') scores 100."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_make_meta())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5000)),
    ):
        result = await sentinel.score("lodahs", ai_suggested=False)

    assert result.score == 100.0
    assert "typosquat_detected" in result.flags


# ── Non-existent + typosquat path (lines 71-72) ───────────────────────────────

@pytest.mark.asyncio
async def test_typosquat_also_nonexistent_scores_95_plus(sentinel: Sentinel) -> None:
    """Package that does not exist and is a typosquat scores >= 95."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=None)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("lodahs", ai_suggested=False)

    assert result.score >= 95.0
    assert "typosquat_detected" in result.flags
    assert "package_not_found" in result.flags


# ── AI-suggested: very_new_package (lines 193-194) ───────────────────────────

@pytest.mark.asyncio
async def test_very_new_package_flag_set(sentinel: Sentinel) -> None:
    """AI-suggested package created 3 days ago triggers very_new_package flag."""
    three_days_ago = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = _make_meta(created=three_days_ago)
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=1000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=True)

    assert "very_new_package" in result.flags
    assert result.score > 0.0


# ── AI-suggested: new_package (lines 195-197, already covered; explicit test) ──

@pytest.mark.asyncio
async def test_new_package_flag_set(sentinel: Sentinel) -> None:
    """AI-suggested package created 15 days ago triggers new_package (7≤age<30) flag."""
    fifteen_days_ago = (datetime.now(timezone.utc) - timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = _make_meta(created=fifteen_days_ago)
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=1000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=True)

    assert "new_package" in result.flags


# ── AI-suggested: very_low_downloads via compute_hallucination_risk (lines 204-205) ──

@pytest.mark.asyncio
async def test_ai_very_low_downloads_flag_set(sentinel: Sentinel) -> None:
    """AI-suggested package with 50 downloads hits very_low_downloads in compute_hallucination_risk."""
    meta = _make_meta(created="2020-01-01T00:00:00Z")
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=50)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=True)

    assert "very_low_downloads" in result.flags


# ── check_registry_existence error paths (lines 143-144, 150-151) ─────────────

@pytest.mark.asyncio
async def test_invalid_created_date_sets_age_none(sentinel: Sentinel) -> None:
    """Malformed created date triggers except ValueError; age_days=None, no crash."""
    meta = {
        "time": {"created": "not-a-valid-date"},
        "maintainers": [{"name": "a"}],
        "repository": {"url": "https://github.com/example/pkg"},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=1000)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert result is not None
    assert result.metadata.get("age_days") is None


@pytest.mark.asyncio
async def test_download_count_exception_handled(sentinel: Sentinel) -> None:
    """Exception from get_download_count is caught; monthly_downloads defaults to 0."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_make_meta())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(side_effect=RuntimeError("network error"))),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert "zero_downloads" in result.flags


# ── compute_hallucination_risk direct unit tests (lines 179-184, 187-188) ─────

def test_compute_hallucination_risk_nonexistent_no_typo(sentinel: Sentinel) -> None:
    """compute_hallucination_risk: not exists, no typo → package_not_found, score 70."""
    score, flags = sentinel.compute_hallucination_risk(
        exists=False, signals={}, is_typo=False, similar_to=""
    )
    assert "package_not_found" in flags
    assert score == 70.0


def test_compute_hallucination_risk_nonexistent_with_typo(sentinel: Sentinel) -> None:
    """compute_hallucination_risk: not exists + typo → both flags, score 85."""
    score, flags = sentinel.compute_hallucination_risk(
        exists=False, signals={}, is_typo=True, similar_to="lodash"
    )
    assert "package_not_found" in flags
    assert "typosquat_detected" in flags
    assert score == 85.0


def test_compute_hallucination_risk_existing_typosquat(sentinel: Sentinel) -> None:
    """compute_hallucination_risk: exists + is_typo → typosquat_detected, score += 40."""
    score, flags = sentinel.compute_hallucination_risk(
        exists=True,
        signals={"age_days": 365, "monthly_downloads": 5000, "has_repository": True},
        is_typo=True,
        similar_to="react",
    )
    assert "typosquat_detected" in flags
    assert score >= 40.0


# ── Maintainer count captured in metadata ────────────────────────────────────

@pytest.mark.asyncio
async def test_maintainer_count_signal(sentinel: Sentinel) -> None:
    """maintainer_count is stored in registry signals regardless of value."""
    single_meta = _make_meta(maintainers=1)
    multi_meta  = _make_meta(maintainers=5)

    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=single_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
    ):
        single_result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=multi_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
    ):
        multi_result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert single_result.metadata.get("maintainer_count") == 1
    assert multi_result.metadata.get("maintainer_count") == 5


# ── Non-AI path: no age or download-risk flags for healthy package ────────────

@pytest.mark.asyncio
async def test_non_ai_package_skips_age_and_download_checks(sentinel: Sentinel) -> None:
    """Non-AI path with healthy signals has no age or download risk flags."""
    meta = _make_meta(created="2015-01-01T00:00:00Z", has_repo=True)
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=500_000)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert result.metadata.get("hallucination_check") == "skipped"
    for flag in ("very_new_package", "new_package", "zero_downloads", "very_low_downloads"):
        assert flag not in result.flags


# ── Known-incident blocklist ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_known_compromised_package_blocked(sentinel: Sentinel) -> None:
    """flatmap-stream must return known_supply_chain_incident without any network call."""
    result = await sentinel.score("flatmap-stream", ai_suggested=False)

    assert result.score == 95.0
    assert "known_supply_chain_incident" in result.flags
    assert "incident" in result.metadata


@pytest.mark.asyncio
async def test_node_ipc_blocked_as_known_incident(sentinel: Sentinel) -> None:
    """node-ipc (peacenotwar, 2022) must be caught by the blocklist."""
    result = await sentinel.score("node-ipc", ai_suggested=False)

    assert result.score == 95.0
    assert "known_supply_chain_incident" in result.flags


@pytest.mark.asyncio
async def test_known_incident_applies_regardless_of_ai_suggested(sentinel: Sentinel) -> None:
    """Blocklist check fires for both human-typed and AI-suggested installs."""
    result_human = await sentinel.score("event-stream", ai_suggested=False)
    result_ai    = await sentinel.score("event-stream", ai_suggested=True)

    assert result_human.score == 95.0
    assert result_ai.score == 95.0
    assert "known_supply_chain_incident" in result_human.flags
    assert "known_supply_chain_incident" in result_ai.flags


# ── OSV vulnerability lookup ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_osv_advisory_boosts_score(sentinel: Sentinel) -> None:
    """An AI-suggested package with OSV advisories should receive a score boost."""
    meta = _make_meta(created="2020-01-01T00:00:00Z")
    osv_result = {"vuln_count": 2, "has_malware": False, "vuln_ids": ["GHSA-abc-123"]}
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=osv_result)),
    ):
        result = await sentinel.score("some-vuln-pkg", ai_suggested=True)

    assert "osv_advisory_found" in result.flags
    assert result.metadata.get("osv_vuln_count") == 2


@pytest.mark.asyncio
async def test_osv_malware_confirmed_flag(sentinel: Sentinel) -> None:
    """has_malware=True from OSV should add osv_malware_confirmed flag and max out score."""
    meta = _make_meta(created="2020-01-01T00:00:00Z")
    osv_result = {"vuln_count": 1, "has_malware": True, "vuln_ids": ["MAL-2022-1"]}
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=500_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=osv_result)),
    ):
        result = await sentinel.score("some-malware-pkg", ai_suggested=True)

    assert "osv_malware_confirmed" in result.flags
    assert result.score == 100.0


@pytest.mark.asyncio
async def test_osv_not_called_for_human_typed(sentinel: Sentinel) -> None:
    """check_osv must not be called for human-typed (non-AI) installs."""
    meta = _make_meta(created="2020-01-01T00:00:00Z")
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=500_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock()) as mock_osv,
    ):
        await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    mock_osv.assert_not_called()
