"""Multi-SIEM backend abstraction (Elasticsearch, OpenSearch, Splunk)."""

from __future__ import annotations

from adept.mcp_server.siem.base import SiemBackend
from adept.mcp_server.siem.models import (
    AlertList,
    AlertSummary,
    DeployRequest,
    DeployResult,
    FieldInfo,
    FieldList,
    QueryValidation,
    SearchHit,
    SearchResult,
)
from adept.mcp_server.siem.registry import build_backends

__all__ = [
    "AlertList",
    "AlertSummary",
    "DeployRequest",
    "DeployResult",
    "FieldInfo",
    "FieldList",
    "QueryValidation",
    "SearchHit",
    "SearchResult",
    "SiemBackend",
    "build_backends",
]
