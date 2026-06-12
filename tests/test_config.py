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


def test_secret_fields_are_usable_but_never_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADEPT_MCP__AUTH_TOKEN", "mcp-supersecret")
    monkeypatch.setenv("ADEPT_ELK__PASSWORD", "elk-supersecret")
    monkeypatch.setenv("ADEPT_INTEL__NVD_API_KEY", "nvd-supersecret")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    # The real value is recoverable where a client actually needs it ...
    assert settings.mcp.auth_token.get_secret_value() == "mcp-supersecret"
    assert settings.elk.password.get_secret_value() == "elk-supersecret"
    assert settings.intel.nvd_api_key.get_secret_value() == "nvd-supersecret"

    # ... but the plaintext never leaks through repr/str or a serialised dump.
    leaked = (
        repr(settings),
        str(settings.mcp),
        str(settings.elk),
        str(settings.model_dump()),
        str(settings.model_dump(mode="json")),
    )
    for rendered in leaked:
        assert "mcp-supersecret" not in rendered
        assert "elk-supersecret" not in rendered
        assert "nvd-supersecret" not in rendered


def test_unset_secret_field_is_falsy() -> None:
    # Presence checks (``if settings.x:``) must still work: an unset secret is
    # falsy, so auth/branch logic that keys off it behaves as before.
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert not settings.mcp.auth_token
    assert not settings.elk.api_key
    assert settings.mcp.auth_token.get_secret_value() == ""
