"""Tests for the Aggregator pillar."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from daemon.models import PillarResult, ScreenRequest, Verdict
from daemon.pillars.aggregator import aggregate, _weighted_score, _verdict
from daemon.config import settings


def _make_pillar(name: str, score: float) -> PillarResult:
    return PillarResult(pillar=name, score=score, signals={})


def test_weighted_score_all_zero():
    pillars = [_make_pillar("contextify", 0), _make_pillar("sentinel", 0), _make_pillar("shield", 0)]
    assert _weighted_score(pillars) == 0.0


def test_weighted_score_all_max():
    pillars = [_make_pillar("contextify", 100), _make_pillar("sentinel", 100), _make_pillar("shield", 100)]
    assert _weighted_score(pillars) == 100.0


def test_weighted_score_mixed():
    # shield=100, sentinel=0, contextify=0
    pillars = [_make_pillar("contextify", 0), _make_pillar("sentinel", 0), _make_pillar("shield", 100)]
    score = _weighted_score(pillars)
    assert score == pytest.approx(45.0)


def test_verdict_block():
    assert _verdict(settings.block_threshold) == Verdict.BLOCK
    assert _verdict(100) == Verdict.BLOCK


def test_verdict_warn():
    assert _verdict(settings.warn_threshold) == Verdict.WARN
    assert _verdict(settings.block_threshold - 1) == Verdict.WARN


def test_verdict_allow():
    assert _verdict(0) == Verdict.ALLOW
    assert _verdict(settings.warn_threshold - 1) == Verdict.ALLOW


@pytest.mark.asyncio
async def test_aggregate_returns_response():
    req = ScreenRequest(package_name="express", version="4.18.2")

    with patch("daemon.pillars.aggregator.contextify", new=AsyncMock(return_value=_make_pillar("contextify", 0))), \
         patch("daemon.pillars.aggregator.sentinel",   new=AsyncMock(return_value=_make_pillar("sentinel", 0))), \
         patch("daemon.pillars.aggregator.shield",     new=AsyncMock(return_value=_make_pillar("shield", 0))):
        response = await aggregate(req)

    assert response.package_name == "express"
    assert response.verdict == Verdict.ALLOW
    assert response.risk_score == 0.0
    assert len(response.pillars) == 3
    assert response.cached is False


@pytest.mark.asyncio
async def test_aggregate_block_on_high_shield():
    req = ScreenRequest(package_name="evil-pkg", version=None)

    with patch("daemon.pillars.aggregator.contextify", new=AsyncMock(return_value=_make_pillar("contextify", 0))), \
         patch("daemon.pillars.aggregator.sentinel",   new=AsyncMock(return_value=_make_pillar("sentinel", 100))), \
         patch("daemon.pillars.aggregator.shield",     new=AsyncMock(return_value=_make_pillar("shield", 100))):
        response = await aggregate(req)

    assert response.verdict == Verdict.BLOCK
    assert response.risk_score >= settings.block_threshold
