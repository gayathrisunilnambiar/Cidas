"""Shared pytest fixtures."""
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from daemon.main import app
from daemon.models import ScreenRequest


@pytest.fixture
def screen_request() -> ScreenRequest:
    return ScreenRequest(package_name="lodash", version="4.17.21", project_root=None)


@pytest.fixture
def malicious_request() -> ScreenRequest:
    return ScreenRequest(package_name="lodashhh", version=None, project_root=None)


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
