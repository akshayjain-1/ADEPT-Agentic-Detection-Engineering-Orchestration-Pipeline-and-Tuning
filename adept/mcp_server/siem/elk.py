"""Elasticsearch / ELK backend (the primary SIEM).

Uses the official ``elasticsearch`` client. The client is created lazily on first
use so that constructing the backend (and unit-testing with an injected fake
client) never requires a live cluster.
"""

from __future__ import annotations

from typing import Any

import httpx

from adept.config.settings import ELKSettings
from adept.mcp_server.siem._lucene import (
    build_lucene_query,
    build_terms_aggregation,
    lucene_query_string,
    parse_mapping_response,
    parse_search_response,
    parse_terms_aggregation,
    parse_validate_query_response,
)
from adept.mcp_server.siem._payloads import kibana_rule_payload
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
from adept.shared.errors import ConfigurationError, ToolExecutionError


class ELKBackend(SiemBackend):
    """Read interface over an Elasticsearch cluster using Lucene queries."""

    siem_id = "elk"
    query_language = "Elasticsearch Lucene"

    def __init__(self, settings: ELKSettings, client: Any = None) -> None:
        super().__init__(default_index=settings.default_index)
        self._settings = settings
        self._client = client
        self._kibana: httpx.Client | None = None

    @property
    def client(self) -> Any:
        """The Elasticsearch client, built on first access."""
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_client(self) -> Any:
        from elasticsearch import Elasticsearch

        kwargs: dict[str, Any] = {
            "hosts": [self._settings.url],
            "verify_certs": self._settings.verify_certs,
            "request_timeout": SEARCH_REQUEST_TIMEOUT,
        }
        if self._settings.ca_cert:
            kwargs["ca_certs"] = self._settings.ca_cert
        if self._settings.api_key:
            kwargs["api_key"] = self._settings.api_key
        elif self._settings.username:
            kwargs["basic_auth"] = (self._settings.username, self._settings.password)
        return Elasticsearch(**kwargs)

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
        body = build_lucene_query(query, earliest, latest)
        try:
            resp = self.client.search(
                index=idx,
                query=body,
                size=self._clamp_size(size),
                terminate_after=SEARCH_TERMINATE_AFTER,
                timeout=SEARCH_TIMEOUT,
            )
        except Exception as exc:
            raise ToolExecutionError(f"ELK search failed: {exc}") from exc
        return parse_search_response(resp, backend=self.siem_id, index=idx)

    def validate_query(self, query: str, *, index: str | None = None) -> QueryValidation:
        idx = index or self.default_index
        try:
            resp = self.client.indices.validate_query(
                index=idx, query=lucene_query_string(query), explain=True
            )
        except Exception as exc:
            return QueryValidation(backend=self.siem_id, valid=False, error=str(exc))
        return parse_validate_query_response(resp, backend=self.siem_id)

    def get_fields(self, *, index: str | None = None, limit: int = 200) -> FieldList:
        idx = index or self.default_index
        try:
            resp = self.client.indices.get_mapping(index=idx)
        except Exception as exc:
            raise ToolExecutionError(f"ELK get_fields failed: {exc}") from exc
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
        query = build_lucene_query("*", f"now-{max(1, lookback_days)}d", "now")
        try:
            resp = self.client.search(
                index=idx,
                query=query,
                size=0,
                aggs=build_terms_aggregation(field, top_n),
            )
        except Exception as exc:
            raise ToolExecutionError(f"ELK aggregate_field failed: {exc}") from exc
        return parse_terms_aggregation(resp, backend=self.siem_id, field=field, index=idx)

    # -- Kibana Detection Engine (deploy / disable / delete) ----------------
    @property
    def kibana(self) -> httpx.Client:
        """An httpx client bound to the Kibana base URL, built on first access."""
        if self._kibana is None:
            self._kibana = self._build_kibana_client()
        return self._kibana

    def _build_kibana_client(self) -> httpx.Client:
        if not self._settings.kibana_url:
            raise ConfigurationError(
                "ELK deploy requires ADEPT_ELK__KIBANA_URL to be set (Kibana base URL)."
            )
        headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
        if self._settings.api_key:
            headers["Authorization"] = f"ApiKey {self._settings.api_key}"
        auth = None
        if not self._settings.api_key and self._settings.username:
            auth = httpx.BasicAuth(self._settings.username, self._settings.password)
        verify: bool | str = self._settings.ca_cert or self._settings.verify_certs
        return httpx.Client(
            base_url=self._settings.kibana_url.rstrip("/"),
            headers=headers,
            auth=auth,
            verify=verify,
            timeout=30.0,
        )

    def _kibana_request(
        self, method: str, path: str, *, json: Any = None, params: Any = None
    ) -> dict[str, Any]:
        try:
            resp = self.kibana.request(method, path, json=json, params=params)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ToolExecutionError(f"Kibana request failed: {exc}") from exc
        if not resp.content:
            return {}
        data: dict[str, Any] = resp.json()
        return data

    def deploy_rule(self, request: DeployRequest) -> DeployResult:
        payload = kibana_rule_payload(request)
        data = self._kibana_request("POST", "/api/detection_engine/rules", json=payload)
        return DeployResult(
            backend=self.siem_id,
            deploy_id=str(data.get("rule_id") or request.rule_id),
            name=request.name,
            status="created",
            enabled=bool(data.get("enabled", request.enabled)),
            detail=str(data.get("id")) if data.get("id") else None,
        )

    def disable_rule(self, deploy_id: str) -> DeployResult:
        data = self._kibana_request(
            "PATCH",
            "/api/detection_engine/rules",
            json={"rule_id": deploy_id, "enabled": False},
        )
        return DeployResult(
            backend=self.siem_id,
            deploy_id=deploy_id,
            name=str(data.get("name") or deploy_id),
            status="disabled",
            enabled=False,
        )

    def delete_rule(self, deploy_id: str) -> DeployResult:
        data = self._kibana_request(
            "DELETE", "/api/detection_engine/rules", params={"rule_id": deploy_id}
        )
        return DeployResult(
            backend=self.siem_id,
            deploy_id=deploy_id,
            name=str(data.get("name") or deploy_id),
            status="deleted",
            enabled=False,
        )

    def list_alerts(self, *, limit: int = 20) -> AlertList:
        try:
            resp = self.client.search(
                index=self._settings.alerts_index,
                query={"match_all": {}},
                size=self._clamp_size(limit),
                sort=[{"@timestamp": {"order": "desc"}}],
            )
        except Exception as exc:
            raise ToolExecutionError(f"ELK list_alerts failed: {exc}") from exc
        parsed = parse_search_response(
            resp, backend=self.siem_id, index=self._settings.alerts_index
        )
        alerts = [
            AlertSummary(
                id=hit.id,
                name=hit.source.get("kibana.alert.rule.name"),
                severity=hit.source.get("kibana.alert.severity"),
                state=hit.source.get("kibana.alert.status"),
                triggered_at=hit.timestamp,
                info=hit.source,
            )
            for hit in parsed.hits
        ]
        return AlertList(backend=self.siem_id, total=parsed.total, alerts=alerts)
