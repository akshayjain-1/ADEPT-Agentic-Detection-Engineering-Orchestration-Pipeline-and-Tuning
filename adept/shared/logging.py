"""Structured logging for ADEPT, built on ``structlog``.

Emits JSON logs in production (easy to ship into the SIEM itself) and
human-friendly colored logs in development. A redaction processor masks values
of sensitive keys so tokens and passwords never end up in log output.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

# Substrings that mark a key as sensitive; their values are redacted.
_SENSITIVE_HINTS = ("token", "password", "api_key", "apikey", "secret", "authorization")
_REDACTED = "***REDACTED***"

# Third-party loggers whose INFO output is per-request noise in the interactive
# agent (every MCP and Ollama HTTP call logs a line). They are dropped to
# WARNING unless ADEPT itself runs at DEBUG, so the chat shows ADEPT's own
# stages instead of raw HTTP traffic.
_NOISY_LOGGERS = ("httpx", "httpcore", "mcp", "langchain_mcp_adapters")

_configured = False


def _quiet_noisy_loggers(level: str) -> None:
    """Raise chatty third-party loggers to WARNING (kept verbose at DEBUG)."""
    if level.upper() == "DEBUG":
        return
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def _redact_processor(
    _logger: Any, _method: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """Redact values whose key name suggests they are a secret."""
    for key in list(event_dict.keys()):
        lowered = key.lower()
        if any(hint in lowered for hint in _SENSITIVE_HINTS) and event_dict[key]:
            event_dict[key] = _REDACTED
    return event_dict


def configure_logging(*, level: str = "INFO", json_logs: bool = True) -> None:
    """Configure structlog and the stdlib logging bridge.

    Idempotent: safe to call multiple times (only the first call applies).

    Args:
        level: Minimum log level name (e.g. ``"INFO"``).
        json_logs: When ``True`` render JSON, otherwise a colored console.
    """
    global _configured
    if _configured:
        return

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact_processor,
    ]

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logging (used by third-party libs) through the same level.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=logging.getLevelNamesMapping().get(level.upper(), logging.INFO),
    )
    _quiet_noisy_loggers(level)
    _configured = True


def get_logger(name: str | None = None) -> Any:
    """Return a bound structlog logger, configuring defaults on first use.

    The logger name is bound into the event dict directly (rather than via
    ``structlog.stdlib.add_logger_name``) so it works with the non-stdlib
    ``PrintLoggerFactory``.
    """
    if not _configured:
        configure_logging()
    logger = structlog.get_logger()
    if name:
        return logger.bind(logger=name)
    return logger
