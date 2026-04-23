"""Tests for the Contextify pillar."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from daemon.models import ScreenRequest
from daemon.pillars.contextify import run, _extract_imports_tree_sitter


def test_extract_imports_regex_fallback():
    source = """
    const fs = require('fs');
    import express from 'express';
    import { useState } from 'react';
    """
    imports = _extract_imports_tree_sitter(source)
    assert "express" in imports
    assert "react" in imports


@pytest.mark.asyncio
async def test_run_no_project_root():
    req = ScreenRequest(package_name="axios", version=None, project_root=None)
    result = await run(req)
    assert result.pillar == "contextify"
    assert result.signals.get("skipped") is True


@pytest.mark.asyncio
async def test_run_empty_project(tmp_path):
    req = ScreenRequest(package_name="axios", version=None, project_root=str(tmp_path))
    result = await run(req)
    assert result.pillar == "contextify"
    assert result.score >= 0


@pytest.mark.asyncio
async def test_run_with_matching_imports(tmp_path):
    src = tmp_path / "index.js"
    src.write_text("const axios = require('axios');\n")

    with patch("daemon.pillars.contextify.EmbeddingService") as MockSvc:
        instance = MockSvc.return_value
        instance.max_similarity = AsyncMock(return_value=0.95)
        req = ScreenRequest(package_name="axios", version=None, project_root=str(tmp_path))
        result = await run(req)

    assert result.score == 0.0  # high similarity → low risk
    assert result.signals["max_similarity_to_existing"] == 0.95


@pytest.mark.asyncio
async def test_run_with_unrelated_package(tmp_path):
    (tmp_path / "app.ts").write_text(
        "import React from 'react';\n" * 15
    )

    with patch("daemon.pillars.contextify.EmbeddingService") as MockSvc:
        instance = MockSvc.return_value
        instance.max_similarity = AsyncMock(return_value=0.05)
        req = ScreenRequest(package_name="totally-unrelated", version=None, project_root=str(tmp_path))
        result = await run(req)

    assert result.score == 20.0
