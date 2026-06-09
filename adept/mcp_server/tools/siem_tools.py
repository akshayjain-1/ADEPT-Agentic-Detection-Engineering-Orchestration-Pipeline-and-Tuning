"""Multi-SIEM read tools exposed over MCP.

These give the Hunt/Log Analyst agent a uniform way to search any configured
SIEM, validate a query before running it, and discover available fields for
query authoring. The ``backend`` argument selects the SIEM (``elk`` /
``opensearch`` / ``splunk``); only enabled backends are addressable.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from adept.mcp_server.context import AppContext
from adept.mcp_server.siem import SiemBackend
from adept.mcp_server.siem.models import DeployRequest, Severity
from adept.mcp_server.tools._annotations import DESTRUCTIVE, READ_ONLY
from adept.shared.errors import AdeptError


def register_siem_tools(mcp: FastMCP, ctx: AppContext) -> None:
    """Register the multi-SIEM read tools on the server."""

    def _resolve(backend: str) -> SiemBackend:
        chosen = ctx.siem_backends.get(backend)
        if chosen is None:
            available = sorted(ctx.siem_backends) or ["(none enabled)"]
            raise ToolError(
                f"SIEM backend '{backend}' is not enabled. Available: {', '.join(available)}"
            )
        return chosen

    @mcp.tool(title="List enabled SIEM backends", annotations=READ_ONLY)
    def siem_list_backends() -> dict[str, object]:
        """Return the SIEM backends that are enabled and their query languages."""
        return {
            "backends": [
                {
                    "id": b.siem_id,
                    "query_language": b.query_language,
                    "default_index": b.default_index,
                }
                for b in ctx.siem_backends.values()
            ]
        }

    @mcp.tool(title="Search a SIEM", annotations=READ_ONLY)
    def siem_search(
        backend: str,
        query: str,
        index: str | None = None,
        size: int = 50,
        earliest: str | None = None,
        latest: str | None = None,
    ) -> dict[str, object]:
        """Search a SIEM and return matching events.

        Args:
            backend: Which SIEM to query (``elk``, ``opensearch``, or ``splunk``).
            query: Lucene (ELK/OpenSearch) or SPL (Splunk) query string.
            index: Index/pattern to search; defaults to the backend's configured index.
            size: Maximum number of events to return (capped at 1000).
            earliest: Optional start of the time window (ISO-8601 or Splunk modifier).
            latest: Optional end of the time window.
        """
        siem = _resolve(backend)
        try:
            result = siem.search(query, index=index, size=size, earliest=earliest, latest=latest)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()

    @mcp.tool(title="Validate a SIEM query", annotations=READ_ONLY)
    def siem_validate_query(
        backend: str, query: str, index: str | None = None
    ) -> dict[str, object]:
        """Check whether a query is syntactically valid without running it."""
        siem = _resolve(backend)
        try:
            result = siem.validate_query(query, index=index)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()

    @mcp.tool(title="List SIEM fields", annotations=READ_ONLY)
    def siem_get_fields(
        backend: str, index: str | None = None, limit: int = 200
    ) -> dict[str, object]:
        """Return the fields available in an index, to help author queries and rules."""
        siem = _resolve(backend)
        try:
            result = siem.get_fields(index=index, limit=limit)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()

    @mcp.tool(title="Deploy a detection (state-changing)", annotations=DESTRUCTIVE)
    def siem_deploy_rule(
        backend: str,
        rule_id: str,
        name: str,
        query: str,
        index: str | None = None,
        description: str = "",
        severity: Severity = "medium",
        interval_minutes: int = 5,
        lookback_minutes: int = 5,
        enabled: bool = True,
        tags: list[str] | None = None,
    ) -> dict[str, object]:
        """Deploy an already-converted detection to a SIEM (creates a live rule).

        State-changing: this should only be invoked after the human approval gate.
        ``query`` must already be in the backend's query language (Lucene for
        ELK/OpenSearch, SPL for Splunk). Use ``siem_delete_rule`` to roll back.
        """
        siem = _resolve(backend)
        request = DeployRequest(
            rule_id=rule_id,
            name=name,
            query=query,
            index=index,
            description=description,
            severity=severity,
            interval_minutes=interval_minutes,
            lookback_minutes=lookback_minutes,
            enabled=enabled,
            tags=tags or [],
        )
        try:
            result = siem.deploy_rule(request)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()

    @mcp.tool(title="Disable a deployed detection (state-changing)", annotations=DESTRUCTIVE)
    def siem_disable_rule(backend: str, deploy_id: str) -> dict[str, object]:
        """Disable a deployed detection without deleting it."""
        siem = _resolve(backend)
        try:
            result = siem.disable_rule(deploy_id)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()

    @mcp.tool(
        title="Delete a deployed detection (rollback, state-changing)",
        annotations=DESTRUCTIVE,
    )
    def siem_delete_rule(backend: str, deploy_id: str) -> dict[str, object]:
        """Delete a deployed detection to roll back a deployment."""
        siem = _resolve(backend)
        try:
            result = siem.delete_rule(deploy_id)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()

    @mcp.tool(title="List recent SIEM alerts", annotations=READ_ONLY)
    def siem_list_alerts(backend: str, limit: int = 20) -> dict[str, object]:
        """Return recently triggered alerts/findings from a SIEM backend."""
        siem = _resolve(backend)
        try:
            result = siem.list_alerts(limit=limit)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()
