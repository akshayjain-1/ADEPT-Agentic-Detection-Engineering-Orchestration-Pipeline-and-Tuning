"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from adept.config.settings import Settings, get_settings


@pytest.fixture
def tmp_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Provide a Settings instance isolated to a temp data dir, no .env."""
    monkeypatch.setenv("ADEPT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADEPT_LOG_JSON", "true")
    get_settings.cache_clear()
    # Build settings without reading a developer .env file on disk.
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    yield settings
    get_settings.cache_clear()
