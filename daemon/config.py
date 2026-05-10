"""Configuration module for the CIDAS daemon.

Reads all settings from environment variables / .env file using pydantic-settings.
Import the singleton via ``get_settings()`` rather than instantiating Settings directly
to avoid re-loading the .env file on every access.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime configuration for the CIDAS daemon.

    Each field maps directly to an environment variable of the same name
    (case-insensitive).  Defaults match the values in .env.example.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Daemon ────────────────────────────────────────────────────────────
    daemon_host: str = "127.0.0.1"
    daemon_port: int = 7355
    log_level: str = Field(default="info", description="debug | info | warning | error")

    # ── Scoring thresholds ────────────────────────────────────────────────
    block_threshold: int = Field(default=80, ge=1, le=100)
    warn_threshold: int = Field(default=40, ge=1, le=100)

    # ── Pillar weights (must sum to ~1.0) ─────────────────────────────────
    context_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    sentinel_weight: float = Field(default=0.40, ge=0.0, le=1.0)
    shield_weight: float = Field(default=0.45, ge=0.0, le=1.0)

    # ── Embeddings ────────────────────────────────────────────────────────
    embedding_model: str = "all-MiniLM-L6-v2"
    chroma_persist_dir: str = ".cidas_chroma"

    # ── SQLite cache ──────────────────────────────────────────────────────
    sqlite_db_path: str = ".cidas_cache.db"

    # ── NPM registry ──────────────────────────────────────────────────────
    npm_registry_url: str = "https://registry.npmjs.org"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached singleton Settings instance.

    The instance is created once on first call and reused for the lifetime of
    the process.  Call ``get_settings.cache_clear()`` in tests to reset.
    """
    return Settings()


def get_admin_config() -> dict:
    """Read ~/.cidas/config.json and return the parsed object.

    Returns an empty dict when the file does not exist or contains invalid JSON.
    This file is controlled by the system administrator (not env vars) and is
    used for settings that must survive across dev-environment resets, such as
    ``bypass_disabled: true`` for CI enforcement.

    Supported keys
    --------------
    bypass_disabled : bool
        When true the npm shim refuses CIDAS_BYPASS=1 and exits with code 1.
    """
    config_path = Path.home() / ".cidas" / "config.json"
    try:
        return json.loads(config_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
