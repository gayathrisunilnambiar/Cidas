"""Tests for the Sentinel pillar.

Covers the hallucination-risk path (ai_suggested=True) and the fast-path
(ai_suggested=False) separately.
"""
from __future__ import annotations

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

@pytest.mark.asyncio
async def test_ai_suggested_nonexistent_package_scores_high(sentinel: Sentinel) -> None:
    """An AI-suggested package that does not exist in the registry should score high."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=None)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("totally-made-up-pkg-xyz123", ai_suggested=True)

    assert isinstance(result, PillarScore)
    assert result.score >= 60.0
    assert "package_not_found" in result.flags


@pytest.mark.asyncio
async def test_human_typed_package_skips_hallucination_check(sentinel: Sentinel) -> None:
    """Human-typed installs should never trigger the hallucination registry check.

    Uses 'webpack' which is an exact match in TOP_PACKAGES (distance == 0) so
    the typosquat check does not fire either, giving a clean score of 0.
    If the network were hit this would fail (no mock), confirming no async
    calls are made for human-typed packages.
    """
    result = await sentinel.score("webpack", ai_suggested=False)
    assert isinstance(result, PillarScore)
    assert result.score == 0.0
    assert result.metadata.get("hallucination_check") == "skipped"


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
    ):
        result = await sentinel.score("lodash", ai_suggested=True)

    assert isinstance(result, PillarScore)
    assert result.score < 30.0


@pytest.mark.asyncio
async def test_new_ai_suggested_package_scores_higher(sentinel: Sentinel) -> None:
    """A brand-new package with zero downloads should receive a higher risk score."""
    new_meta = {
        "time": {"created": "2026-04-20T00:00:00Z"},
        "maintainers": [{"name": "anon"}],
        "repository": None,
        "versions": {"0.0.1": {}},
        "dist-tags": {"latest": "0.0.1"},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=new_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("brand-new-package", ai_suggested=True)

    assert result.score >= 40.0
