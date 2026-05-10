"""Tests for the Aggregator pillar.

Verifies weighted scoring, decision mapping, and explanation generation without
any I/O calls.
"""
from __future__ import annotations

import pytest

from daemon.config import get_settings
from daemon.models import PillarScore
from daemon.pillars.aggregator import Aggregator


@pytest.fixture
def aggregator() -> Aggregator:
    return Aggregator()


@pytest.fixture
def settings():
    return get_settings()


def _ps(score: float, flags: list[str] | None = None) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=flags or [], metadata={})


# ── Score computation tests ───────────────────────────────────────────────────

def test_all_low_scores_allow(aggregator: Aggregator, settings) -> None:
    """All-zero pillar scores must result in ALLOW with risk_score == 0."""
    risk, explanation = aggregator.aggregate(_ps(0), _ps(0), _ps(0), settings)
    assert risk == 0.0
    assert aggregator.get_decision(risk, settings) == "ALLOW"
    assert "passed" in explanation.lower() or "allow" in explanation.lower()


def test_high_contextify_warns(aggregator: Aggregator, settings) -> None:
    """Pillar combination that produces a score in [warn_threshold, block_threshold) → WARN."""
    # sentinel=60 → 0.40*60=24, shield=40 → 0.45*40=18, contextify=0 → total=42 → WARN
    risk, explanation = aggregator.aggregate(_ps(0), _ps(60), _ps(40), settings)
    assert settings.warn_threshold <= risk < settings.block_threshold
    assert aggregator.get_decision(risk, settings) == "WARN"
    assert explanation  # not empty


def test_any_pillar_above_block_threshold_blocks(aggregator: Aggregator, settings) -> None:
    """When the weighted score reaches block_threshold the decision must be BLOCK."""
    # sentinel=100, shield=100 → 0.40*100 + 0.45*100 = 85 → BLOCK
    risk, explanation = aggregator.aggregate(_ps(0), _ps(100), _ps(100), settings)
    assert risk >= settings.block_threshold
    assert aggregator.get_decision(risk, settings) == "BLOCK"


def test_hallucinated_package_overrides_to_block(aggregator: Aggregator, settings) -> None:
    """A nonexistent AI-suggested package must always resolve to BLOCK."""
    sen = PillarScore(
        score=70.0, confidence=0.85,
        flags=["package_not_found"],
        metadata={"ai_suggested": True},
    )
    risk, _ = aggregator.aggregate(_ps(15), sen, _ps(0), settings)
    assert aggregator.get_decision(risk, settings) == "BLOCK"
    assert risk >= settings.block_threshold


def test_explanation_contains_flags(aggregator: Aggregator, settings) -> None:
    """The explanation string must mention signal flags when they are present."""
    ctx = _ps(20, flags=["unfamiliar_in_mature_project"])
    sen = _ps(50, flags=["typosquat_detected", "very_new_package"])
    shi = _ps(0, flags=[])
    _, explanation = aggregator.aggregate(ctx, sen, shi, settings)
    assert "typosquat_detected" in explanation or "unfamiliar_in_mature_project" in explanation


def test_score_capped_at_100(aggregator: Aggregator, settings) -> None:
    """Weighted sum must never exceed 100 even if pillar scores are at maximum."""
    risk, _ = aggregator.aggregate(_ps(100), _ps(100), _ps(100), settings)
    assert risk == 100.0


def test_get_decision_boundaries(aggregator: Aggregator, settings) -> None:
    """Decision boundaries must be respected exactly at the threshold values."""
    assert aggregator.get_decision(settings.warn_threshold - 1, settings) == "ALLOW"
    assert aggregator.get_decision(settings.warn_threshold, settings) == "WARN"
    assert aggregator.get_decision(settings.block_threshold - 1, settings) == "WARN"
    assert aggregator.get_decision(settings.block_threshold, settings) == "BLOCK"
