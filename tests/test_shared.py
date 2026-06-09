"""Tests for shared utilities (cache, rate limiter, notifier, logging)."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest
from adept.config.settings import NotifySettings
from adept.shared.cache import DiskCache
from adept.shared.logging import _quiet_noisy_loggers, _redact_processor, configure_logging
from adept.shared.notify import Notifier
from adept.shared.ratelimit import AsyncRateLimiter


def test_disk_cache_set_get(tmp_path: Path) -> None:
    cache = DiskCache(tmp_path, namespace="t")
    cache.set("k", {"a": 1}, ttl_seconds=60)
    assert cache.get("k") == {"a": 1}


def test_disk_cache_expiry(tmp_path: Path) -> None:
    cache = DiskCache(tmp_path, namespace="t")
    cache.set("k", "v", ttl_seconds=-1)  # already expired
    assert cache.get("k") is None


def test_disk_cache_miss(tmp_path: Path) -> None:
    cache = DiskCache(tmp_path, namespace="t")
    assert cache.get("absent") is None


def test_redaction_masks_secrets() -> None:
    event = {"event": "login", "auth_token": "supersecret", "user": "alice"}
    out = _redact_processor(None, "info", event)
    assert out["auth_token"] == "***REDACTED***"
    assert out["user"] == "alice"


def test_configure_logging_idempotent() -> None:
    configure_logging(level="DEBUG", json_logs=True)
    configure_logging(level="INFO", json_logs=False)  # must not raise


def test_quiet_noisy_loggers_silences_http_chatter() -> None:
    # The per-request HTTP logs from the MCP/Ollama clients are noise in the
    # interactive agent and must be dropped to WARNING at INFO and below.
    logging.getLogger("httpx").setLevel(logging.INFO)
    _quiet_noisy_loggers("INFO")
    assert logging.getLogger("httpx").level == logging.WARNING


def test_quiet_noisy_loggers_stays_verbose_at_debug() -> None:
    logging.getLogger("httpcore").setLevel(logging.DEBUG)
    _quiet_noisy_loggers("DEBUG")
    assert logging.getLogger("httpcore").level == logging.DEBUG


async def test_rate_limiter_allows_burst() -> None:
    limiter = AsyncRateLimiter(rate=100, capacity=5)
    start = time.monotonic()
    for _ in range(5):
        await limiter.acquire()
    assert time.monotonic() - start < 0.1  # burst should be near-instant


async def test_notifier_none_backend_is_noop() -> None:
    notifier = Notifier(NotifySettings(backend="none"))
    assert await notifier.send("title", "msg") is True


def test_rate_limiter_rejects_oversized_request() -> None:
    limiter = AsyncRateLimiter(rate=10, capacity=5)
    with pytest.raises(ValueError):
        # 6 > capacity of 5 -> impossible to ever satisfy
        import asyncio

        asyncio.run(limiter.acquire(6))
