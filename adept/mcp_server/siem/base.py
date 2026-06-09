"""Abstract base class for SIEM backends.

A backend wraps one SIEM's client and exposes a small, uniform read surface:
search, query validation, and field discovery. State-changing operations
(rule deployment, rollback) are intentionally *not* part of this base yet; they
are gated behind human approval and added once the per-SIEM deployment mechanism
is confirmed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from adept.mcp_server.siem.models import (
    AlertList,
    DeployRequest,
    DeployResult,
    FieldAggregation,
    FieldList,
    QueryValidation,
    SearchResult,
)
from adept.shared.errors import ToolExecutionError

#: Hard cap on the number of hits any single search may return.
MAX_SEARCH_SIZE = 1000

#: Stop scanning each shard after this many documents have been collected. This
#: bounds the cost of an expensive ad-hoc query so it cannot tie up the cluster.
SEARCH_TERMINATE_AFTER = 100_000

#: Server-side (cluster) timeout for a single search request.
SEARCH_TIMEOUT = "30s"

#: Client-side HTTP timeout, in seconds, for SIEM requests.
SEARCH_REQUEST_TIMEOUT = 30.0


class SiemBackend(ABC):
    """Uniform read interface over a single SIEM."""

    #: Stable identifier (``elk`` / ``opensearch`` / ``splunk``).
    siem_id: ClassVar[str]
    #: Human-readable query language name, for prompts and packets.
    query_language: ClassVar[str]

    def __init__(self, *, default_index: str) -> None:
        self.default_index = default_index

    @staticmethod
    def _clamp_size(size: int) -> int:
        """Constrain a requested result size to a safe range."""
        return max(1, min(size, MAX_SEARCH_SIZE))

    @abstractmethod
    def search(
        self,
        query: str,
        *,
        index: str | None = None,
        size: int = 50,
        earliest: str | None = None,
        latest: str | None = None,
    ) -> SearchResult:
        """Run a search and return matching events."""

    @abstractmethod
    def validate_query(self, query: str, *, index: str | None = None) -> QueryValidation:
        """Check whether a query is syntactically valid."""

    @abstractmethod
    def get_fields(self, *, index: str | None = None, limit: int = 200) -> FieldList:
        """Return the fields available in an index, for query authoring."""

    @abstractmethod
    def deploy_rule(self, request: DeployRequest) -> DeployResult:
        """Deploy a converted detection. State-changing; runs after HITL approval."""

    @abstractmethod
    def disable_rule(self, deploy_id: str) -> DeployResult:
        """Disable a deployed detection without deleting it."""

    @abstractmethod
    def delete_rule(self, deploy_id: str) -> DeployResult:
        """Delete a deployed detection (used to roll back a deployment)."""

    @abstractmethod
    def list_alerts(self, *, limit: int = 20) -> AlertList:
        """Return recently triggered alerts/findings from this backend."""

    def aggregate_field(
        self,
        field: str,
        *,
        index: str | None = None,
        lookback_days: int = 7,
        top_n: int = 10,
    ) -> FieldAggregation:
        """Profile a field's volume and cardinality over a recent time window.

        Used for baseline/noise analysis. Backends that support aggregation
        override this; the default refuses so a backend never silently returns
        empty results.
        """
        raise ToolExecutionError(f"{self.siem_id} does not support field aggregation")
