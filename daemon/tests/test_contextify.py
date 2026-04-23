"""Tests for the Contextify pillar.

Uses mock embeddings (fixed unit vectors) to avoid loading the sentence-transformer
model during CI, keeping the suite fast and reproducible.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from daemon.models import PillarScore
from daemon.pillars.contextify import Contextify


@pytest.fixture
def contextify() -> Contextify:
    return Contextify()


# ── Unit tests (no I/O) ───────────────────────────────────────────────────────

def test_score_returns_pillar_score(contextify: Contextify) -> None:
    """load_project_fingerprint + compute_score must always return a PillarScore."""
    score = contextify.compute_score(similarity=0.8, domain_count=5)
    assert isinstance(score, tuple)
    risk, flags = score
    assert 0.0 <= risk <= 100.0
    assert isinstance(flags, list)


def test_unfamiliar_package_scores_high(contextify: Contextify, sample_project_path) -> None:
    """A package with very low similarity to the project should score highly."""
    # Fingerprint has >10 domains after reading a real package.json
    domains = contextify.load_project_fingerprint(str(sample_project_path))
    assert len(domains) >= 3

    # Patch embed functions to return orthogonal vectors
    import numpy as np
    project_vec = [1.0, 0.0, 0.0]
    pkg_vec = [0.0, 1.0, 0.0]  # orthogonal → similarity ≈ 0

    with (
        patch("daemon.pillars.contextify.embed_text", return_value=pkg_vec),
        patch("daemon.pillars.contextify.cosine_similarity", return_value=0.02),
        patch("daemon.pillars.contextify.get_package_metadata", return_value=None),
    ):
        risk, flags = contextify.compute_score(similarity=0.02, domain_count=len(domains))

    assert risk >= 15.0
    assert len(flags) > 0


def test_familiar_package_scores_low(contextify: Contextify, sample_project_path) -> None:
    """A package whose embedding closely matches the project should score near zero."""
    risk, flags = contextify.compute_score(similarity=0.92, domain_count=5)
    assert risk == 0.0
    assert flags == []


@pytest.mark.asyncio
async def test_missing_project_path_handled_gracefully(contextify: Contextify) -> None:
    """An empty project_path must not raise; should return a PillarScore with low-risk default."""
    result = await contextify.score("some-package", project_path="")
    assert isinstance(result, PillarScore)
    assert 0.0 <= result.score <= 100.0
    assert "no_project_path" in result.flags


@pytest.mark.asyncio
async def test_score_with_mock_embeddings(contextify: Contextify, sample_project_path) -> None:
    """Full async score() should use mocked embeddings and return a valid PillarScore."""
    with (
        patch("daemon.pillars.contextify.embed_text", return_value=[0.5, 0.5, 0.5]),
        patch("daemon.pillars.contextify.cosine_similarity", return_value=0.75),
        patch("daemon.pillars.contextify.get_package_metadata", return_value={"description": "utility library"}),
    ):
        result = await contextify.score("lodash", str(sample_project_path))

    assert isinstance(result, PillarScore)
    assert result.score == 0.0  # similarity 0.75 >= 0.65 → no risk
    assert result.confidence > 0
