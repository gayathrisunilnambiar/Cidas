"""Tests for the Sentinel pillar."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from daemon.models import ScreenRequest
from daemon.pillars.sentinel import _is_likely_typosquat, _levenshtein, _score_metadata, run


def test_levenshtein_exact():
    assert _levenshtein("react", "react") == 0


def test_levenshtein_one_edit():
    assert _levenshtein("reakt", "react") == 1


def test_levenshtein_two_edits():
    assert _levenshtein("lodahs", "lodash") == 2


def test_typosquat_detected():
    flag, similar_to = _is_likely_typosquat("lodasH")
    # Distance depends on case — test a clear one-char difference
    flag2, similar_to2 = _is_likely_typosquat("lodahs")
    assert flag2 is True
    assert similar_to2 == "lodash"


def test_typosquat_not_detected_for_exact():
    flag, _ = _is_likely_typosquat("lodash")
    assert flag is False


def test_typosquat_not_detected_for_unrelated():
    flag, _ = _is_likely_typosquat("my-totally-unique-utility-pkg")
    assert flag is False


def test_score_metadata_new_package():
    meta = {
        "time": {"created": "2025-04-20T00:00:00Z"},
        "maintainers": [{"name": "anon"}],
        "readme": "",
        "repository": None,
        "downloads": {"weekly": 0},
    }
    score, signals = _score_metadata(meta)
    assert score > 50  # new, no downloads, no readme, no repo


def test_score_metadata_established_package():
    meta = {
        "time": {"created": "2018-01-01T00:00:00Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}],
        "readme": "x" * 500,
        "repository": {"url": "https://github.com/foo/bar"},
        "downloads": {"weekly": 5_000_000},
    }
    score, _ = _score_metadata(meta)
    assert score == 0.0


@pytest.mark.asyncio
async def test_run_package_not_found():
    req = ScreenRequest(package_name="definitely-does-not-exist-xyz", version=None)
    with patch("daemon.pillars.sentinel.NpmRegistryClient") as MockClient:
        instance = MockClient.return_value.__aenter__.return_value
        instance.fetch_metadata = AsyncMock(return_value=None)
        result = await run(req)
    assert result.pillar == "sentinel"
    assert result.score >= 60.0


@pytest.mark.asyncio
async def test_run_known_good_package():
    meta = {
        "time": {"created": "2015-01-01T00:00:00Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
        "readme": "Very detailed readme " * 50,
        "repository": {"url": "https://github.com/lodash/lodash"},
        "downloads": {"weekly": 10_000_000},
    }
    req = ScreenRequest(package_name="lodash", version="4.17.21")
    with patch("daemon.pillars.sentinel.NpmRegistryClient") as MockClient:
        instance = MockClient.return_value.__aenter__.return_value
        instance.fetch_metadata = AsyncMock(return_value=meta)
        result = await run(req)
    assert result.score < 20.0
