"""Tests for Shield's package-file scan (download + extract + static analysis).

Uses small fixture tarballs in tests/fixtures/ instead of hitting the real
npm registry, so the suite runs offline. ``download_tarball`` is monkey-patched
to copy the appropriate fixture into the temp directory the scanner created.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from daemon.pillars import shield as shield_module
from daemon.pillars.shield import FILE_SCAN_WEIGHT, Shield

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN_TGZ = FIXTURES / "clean-pkg-1.0.0.tgz"
EVIL_TGZ  = FIXTURES / "evil-pkg-1.0.0.tgz"


@pytest.fixture(autouse=True)
def _no_admin_config(monkeypatch):
    """Pin admin config to defaults — the file scan is enabled by default."""
    monkeypatch.setattr(shield_module, "get_admin_config", lambda: {})


def _mock_download(src: Path):
    """Build an async download_tarball replacement that copies *src* into place."""
    async def _impl(url: str, dest_path: str) -> bool:
        shutil.copyfile(src, dest_path)
        return True
    return _impl


# ── Clean package: file scan should contribute zero ──────────────────────────

@pytest.mark.asyncio
async def test_clean_package_file_scan_scores_zero(monkeypatch):
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(CLEAN_TGZ))
    score, flags, summary = await Shield().scan_package_files(
        "https://registry.npmjs.org/clean-pkg/-/clean-pkg-1.0.0.tgz"
    )
    assert score == 0.0
    assert flags == []
    assert summary["files_scanned"] == 1  # only index.js
    assert summary["skipped"] is None


# ── Malicious package: env-exfil-near-http pattern fires ─────────────────────

@pytest.mark.asyncio
async def test_env_exfil_pattern_detected_in_file(monkeypatch):
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(EVIL_TGZ))
    score, flags, summary = await Shield().scan_package_files(
        "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
    )
    assert "env_exfil_near_http" in flags
    assert "dns_long_subdomain" in flags
    assert score > 0
    assert summary["files_scanned"] >= 1
    assert summary["flags"] == len(flags)


# ── Temp directory cleanup is unconditional ──────────────────────────────────

@pytest.mark.asyncio
async def test_temp_dir_cleaned_up_on_success(monkeypatch):
    captured: list[str] = []
    real_mkdtemp = shield_module.tempfile.mkdtemp

    def _spy_mkdtemp(*args, **kwargs):
        d = real_mkdtemp(*args, **kwargs)
        captured.append(d)
        return d

    monkeypatch.setattr(shield_module.tempfile, "mkdtemp", _spy_mkdtemp)
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(CLEAN_TGZ))

    await Shield().scan_package_files("https://example.invalid/x.tgz")

    assert captured, "scan_package_files did not allocate a temp dir"
    for d in captured:
        assert not os.path.exists(d), f"temp dir {d} survived a successful scan"


@pytest.mark.asyncio
async def test_temp_dir_cleaned_up_on_extract_failure(monkeypatch):
    """If extraction throws, the finally block must still remove the temp dir."""
    captured: list[str] = []
    real_mkdtemp = shield_module.tempfile.mkdtemp

    def _spy_mkdtemp(*args, **kwargs):
        d = real_mkdtemp(*args, **kwargs)
        captured.append(d)
        return d

    monkeypatch.setattr(shield_module.tempfile, "mkdtemp", _spy_mkdtemp)
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(CLEAN_TGZ))

    with patch.object(Shield, "_safe_extract", side_effect=OSError("boom")):
        score, flags, summary = await Shield().scan_package_files("https://example.invalid/x.tgz")

    assert score == 0.0
    assert summary["skipped"] == "extract_failed"
    assert captured
    for d in captured:
        assert not os.path.exists(d)


# ── Admin config disables the file scan ──────────────────────────────────────

@pytest.mark.asyncio
async def test_file_scan_disabled_by_admin_config(monkeypatch):
    monkeypatch.setattr(shield_module, "get_admin_config",
                        lambda: {"package_file_scan": False})

    # If download_tarball gets called at all, the test fails: the scan must
    # short-circuit before any network or filesystem activity.
    async def _explode(*_a, **_kw):
        raise AssertionError("download_tarball must not be called when scan disabled")
    monkeypatch.setattr(shield_module, "download_tarball", _explode)

    score, flags, summary = await Shield().scan_package_files(
        "https://registry.npmjs.org/anything/-/anything-1.0.0.tgz"
    )
    assert score == 0.0
    assert flags == []
    assert summary["skipped"] == "disabled_by_admin"


# ── FILE_SCAN_WEIGHT actually applied in the combined score ──────────────────

@pytest.mark.asyncio
async def test_file_scan_weighted_into_overall_score(monkeypatch):
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(EVIL_TGZ))
    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "scripts": {},
            "dist": {"tarball": "https://registry.example.com/evil/-/evil-1.0.0.tgz"},
        }},
        "readme": "",
        "description": "",
    }
    result = await Shield().score("evil-pkg", package_metadata=meta)

    file_score = result.metadata["file_score"]
    assert file_score > 0
    # Lifecycle scripts and injection scores are zero in this fixture, so the
    # full PillarScore.score must equal file_score * FILE_SCAN_WEIGHT (capped).
    assert result.score == pytest.approx(min(file_score * FILE_SCAN_WEIGHT, 100.0), abs=0.01)
    # ScanResponse-bound metadata is populated for the VS Code panel.
    assert result.metadata["tarball_url"] == "https://registry.example.com/evil/-/evil-1.0.0.tgz"
    assert result.metadata["file_scan_summary"]["flags"] >= 2


# ── Path-traversal guard ─────────────────────────────────────────────────────

def test_safe_extract_rejects_path_traversal(tmp_path):
    """A tarball entry with ../ in its name must be refused, not silently extracted."""
    import io
    import tarfile

    bad_tgz = tmp_path / "bad.tgz"
    with tarfile.open(bad_tgz, "w:gz") as tf:
        data = b"pwned"
        info = tarfile.TarInfo(name="../escaped.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(tarfile.TarError):
        Shield._safe_extract(str(bad_tgz), str(dest))
