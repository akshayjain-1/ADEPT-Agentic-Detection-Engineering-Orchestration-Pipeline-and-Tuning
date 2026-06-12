"""Wazuh Indexer / OpenSearch backend.

Mirrors the Elasticsearch backend but uses the ``opensearch-py`` client, whose
search and validate APIs take a ``body`` argument rather than keyword DSL.
"""

from __future__ import annotations

from typing import Any

from adept.config.settings import OpenSearchSettings
from adept.mcp_server.siem._lucene import (
    build_lucene_query,
    build_terms_aggregation,
    lucene_query_string,
    parse_mapping_response,
    parse_search_response,
    parse_terms_aggregation,
    parse_validate_query_response,
)
from adept.mcp_server.siem._payloads import opensearch_monitor_payload
from adept.mcp_server.siem.base import (
    SEARCH_REQUEST_TIMEOUT,
    SEARCH_TERMINATE_AFTER,
    SEARCH_TIMEOUT,
    SiemBackend,
)
from adept.mcp_server.siem.models import (
    AlertList,
    AlertSummary,
    DeployRequest,
    DeployResult,
    FieldAggregation,
    FieldList,
    QueryValidation,
    SearchResult,
)
from adept.shared.errors import ToolExecutionError


class OpenSearchBackend(SiemBackend):
    """Read interface over an OpenSearch (Wazuh Indexer) cluster."""

    siem_id = "opensearch"
    query_language = "OpenSearch Lucene"

    def __init__(self, settings: OpenSearchSettings, client: Any = None) -> None:
        super().__init__(default_index=settings.default_index)
        self._settings = settings
        self._client = client

    @property
    def client(self) -> Any:
        """The OpenSearch client, built on first access."""
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_client(self) -> Any:
        from opensearchpy import OpenSearch

        kwargs: dict[str, Any] = {
            "hosts": [self._settings.url],
            "verify_certs": self._settings.verify_certs,
            "http_auth": (self._settings.username, self._settings.password.get_secret_value()),
            "timeout": SEARCH_REQUEST_TIMEOUT,
        }
        if self._settings.ca_cert:
            kwargs["ca_certs"] = self._settings.ca_cert
        return OpenSearch(**kwargs)

    def search(
        self,
        query: str,
        *,
        index: str | None = None,
        size: int = 50,
        earliest: str | None = None,
        latest: str | None = None,
    ) -> SearchResult:
        idx = index or self.default_index
        body = {
            "query": build_lucene_query(query, earliest, latest),
            "size": self._clamp_size(size),
            "terminate_after": SEARCH_TERMINATE_AFTER,
            "timeout": SEARCH_TIMEOUT,
        }
        try:
            resp = self.client.search(index=idx, body=body)
        except Exception as exc:
            raise ToolExecutionError(f"OpenSearch search failed: {exc}") from exc
        return parse_search_response(resp, backend=self.siem_id, index=idx)

    def validate_query(self, query: str, *, index: str | None = None) -> QueryValidation:
        idx = index or self.default_index
        try:
            resp = self.client.indices.validate_query(
                index=idx,
                body={"query": lucene_query_string(query)},
                explain=True,
            )
        except Exception as exc:
            return QueryValidation(backend=self.siem_id, valid=False, error=str(exc))
        return parse_validate_query_response(resp, backend=self.siem_id)

    def get_fields(self, *, index: str | None = None, limit: int = 200) -> FieldList:
        idx = index or self.default_index
        try:
            resp = self.client.indices.get_mapping(index=idx)
        except Exception as exc:
            raise ToolExecutionError(f"OpenSearch get_fields failed: {exc}") from exc
        return parse_mapping_response(resp, backend=self.siem_id, index=idx, limit=limit)

    def aggregate_field(
        self,
        field: str,
        *,
        index: str | None = None,
        lookback_days: int = 7,
        top_n: int = 10,
    ) -> FieldAggregation:
        idx = index or self.default_index
        body = {
            "size": 0,
            "query": build_lucene_query("*", f"now-{max(1, lookback_days)}d", "now"),
            "aggs": build_terms_aggregation(field, top_n),
        }
        try:
            resp = self.client.search(index=idx, body=body)
        except Exception as exc:
            raise ToolExecutionError(f"OpenSearch aggregate_field failed: {exc}") from exc
        return parse_terms_aggregation(resp, backend=self.siem_id, field=field, index=idx)

    # -- Alerting plugin (deploy / disable / delete) ------------------------
    def _alerting_request(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        try:
            data: dict[str, Any] = self.client.transport.perform_request(method, path, body=body)
        except Exception as exc:
            raise ToolExecutionError(f"OpenSearch alerting request failed: {exc}") from exc
        return data

    def deploy_rule(self, request: DeployRequest) -> DeployResult:
        payload = opensearch_monitor_payload(request)
        data = self._alerting_request("POST", "/_plugins/_alerting/monitors", payload)
        monitor_id = str(data.get("_id", ""))
        return DeployResult(
            backend=self.siem_id,
            deploy_id=monitor_id,
            name=request.name,
            status="created",
            enabled=request.enabled,
        )

    def disable_rule(self, deploy_id: str) -> DeployResult:
        current = self._alerting_request("GET", f"/_plugins/_alerting/monitors/{deploy_id}")
        monitor = current.get("monitor")
        if not isinstance(monitor, dict):
            raise ToolExecutionError(f"OpenSearch monitor '{deploy_id}' not found")
        monitor["enabled"] = False
        self._alerting_request("PUT", f"/_plugins/_alerting/monitors/{deploy_id}", monitor)
        return DeployResult(
            backend=self.siem_id,
            deploy_id=deploy_id,
            name=str(monitor.get("name") or deploy_id),
            status="disabled",
            enabled=False,
        )

    def delete_rule(self, deploy_id: str) -> DeployResult:
        self._alerting_request("DELETE", f"/_plugins/_alerting/monitors/{deploy_id}")
        return DeployResult(
            backend=self.siem_id,
            deploy_id=deploy_id,
            name=deploy_id,
            status="deleted",
            enabled=False,
        )

    def list_alerts(self, *, limit: int = 20) -> AlertList:
        data = self._alerting_request("GET", "/_plugins/_alerting/monitors/alerts")
        raw_alerts = data.get("alerts") or []
        alerts = [
            AlertSummary(
                id=item.get("id"),
                name=item.get("trigger_name") or item.get("monitor_name"),
                severity=item.get("severity"),
                state=item.get("state"),
                triggered_at=item.get("start_time"),
                info=item,
            )
            for item in raw_alerts[: max(0, limit)]
        ]
        return AlertList(
            backend=self.siem_id,
            total=int(data.get("totalAlerts") or len(alerts)),
            alerts=alerts,
        )
