"""Tests for configuration loading and parsing."""

from __future__ import annotations

import pytest
from adept.config.settings import Settings


def test_defaults_have_elk_enabled() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert "elk" in settings.enabled_siems()


def test_nested_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADEPT_ELK__URL", "https://elk.example:9200")
    monkeypatch.setenv("ADEPT_OPENSEARCH__ENABLED", "true")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.elk.url == "https://elk.example:9200"
    assert set(settings.enabled_siems()) == {"elk", "opensearch"}


def test_csv_list_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADEPT_INTEL__RSS_FEEDS", "https://a.example/x, https://b.example/y")
    monkeypatch.setenv("ADEPT_SIGMA__PROTECTED_BRANCHES", "main, release, prod")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.intel.rss_feeds == ["https://a.example/x", "https://b.example/y"]
    assert settings.sigma.protected_branches == ["main", "release", "prod"]


def test_attack_defaults_are_safe() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.attack.require_approval is True
    assert settings.attack.dry_run_default is True
    assert settings.attack.atomic_enabled is False
