"""Typed exception hierarchy for ADEPT.

A small, purpose-built set of errors so that callers (and the MCP tool layer)
can distinguish configuration problems, disabled backends, security policy
violations and runtime tool failures.
"""

from __future__ import annotations


class AdeptError(Exception):
    """Base class for all ADEPT errors."""


class ConfigurationError(AdeptError):
    """Raised when configuration is missing or invalid."""


class BackendNotEnabledError(AdeptError):
    """Raised when a SIEM (or other) backend is requested but not enabled."""


class SecurityError(AdeptError):
    """Raised when an operation violates a security guardrail.

    Examples: an attack-simulation request without approval, a fetch to a
    domain outside the allowlist, or a commit to a protected branch without
    the required confirmation.
    """


class ValidationFailedError(AdeptError):
    """Raised when a Sigma rule fails structural validation or linting."""


class ToolExecutionError(AdeptError):
    """Raised when an MCP tool fails during execution."""


class ModelTimeoutError(AdeptError):
    """Raised when the local LLM does not respond within the configured timeout.

    The underlying async ``httpx.ReadTimeout`` carries an empty message, which
    surfaces as a blank ``Turn failed:`` line in the CLI; this typed error
    replaces it with actionable guidance.
    """
