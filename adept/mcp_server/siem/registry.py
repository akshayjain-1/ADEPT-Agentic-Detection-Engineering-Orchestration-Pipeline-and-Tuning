"""SIEM backend registry.

Builds the set of enabled SIEM backends from configuration. Backends are
constructed without opening any connections; clients are created lazily on first
use.
"""

from __future__ import annotations

from adept.config.settings import Settings
from adept.mcp_server.siem.base import SiemBackend
from adept.mcp_server.siem.elk import ELKBackend
from adept.mcp_server.siem.opensearch import OpenSearchBackend
from adept.mcp_server.siem.splunk import SplunkBackend


def build_backends(settings: Settings) -> dict[str, SiemBackend]:
    """Return a mapping of SIEM id to backend for every enabled SIEM."""
    backends: dict[str, SiemBackend] = {}
    if settings.elk.enabled:
        backends["elk"] = ELKBackend(settings.elk)
    if settings.opensearch.enabled:
        backends["opensearch"] = OpenSearchBackend(settings.opensearch)
    if settings.splunk.enabled:
        backends["splunk"] = SplunkBackend(settings.splunk)
    return backends
