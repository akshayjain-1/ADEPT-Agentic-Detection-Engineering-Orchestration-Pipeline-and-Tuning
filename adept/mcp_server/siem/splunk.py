"""Splunk backend using the official ``splunklib`` SDK.

Searches run as oneshot jobs returning JSON; query validation uses the search
parser endpoint; field discovery uses the ``fieldsummary`` SPL command. The
``service`` (a ``splunklib.client.Service``) is built lazily and may be injected
for testing.
"""

from __future__ import annotations

from typing import Any

from adept.config.settings import SplunkSettings
from adept.mcp_server.siem._payloads import splunk_saved_search_args
from adept.mcp_server.siem.base import SiemBackend
from adept.mcp_server.siem.models import (
    AlertList,
    AlertSummary,
    DeployRequest,
    DeployResult,
    FieldAggregation,
    FieldInfo,
    FieldList,
    QueryValidation,
    SearchHit,
    SearchResult,
)
from adept.shared.errors import ToolExecutionError


def normalize_spl(query: str, index: str) -> str:
    """Normalise a user query into runnable SPL.

    A query that already starts with ``search`` or a leading pipe (``|``) is left
    as-is; otherwise it is wrapped as ``search index=<index> <query>`` so the
    ``index`` argument is honoured.
    """
    stripped = query.strip()
    lowered = stripped.lower()
    if lowered.startswith("|") or lowered.startswith("search "):
        return stripped
    return f"search index={index} {stripped}"


def _read_json_results(stream: Any) -> list[dict[str, Any]]:
    """Read a Splunk JSON results stream into a list of result rows."""
    import splunklib.results as results

    rows: list[dict[str, Any]] = []
    for item in results.JSONResultsReader(stream):
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _to_int(value: Any) -> int:
    """Coerce a Splunk string/number result into an int, defaulting to 0."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


class SplunkBackend(SiemBackend):
    """Read interface over a Splunk deployment using SPL."""

    siem_id = "splunk"
    query_language = "SPL"

    def __init__(self, settings: SplunkSettings, service: Any = None) -> None:
        super().__init__(default_index=settings.default_index)
        self._settings = settings
        self._service = service

    @property
    def service(self) -> Any:
        """The Splunk service connection, built on first access."""
        if self._service is None:
            self._service = self._build_service()
        return self._service

    def _build_service(self) -> Any:
        import splunklib.client as splunk_client

        kwargs: dict[str, Any] = {
            "host": self._settings.host,
            "port": self._settings.port,
            "scheme": self._settings.scheme,
            "verify": self._settings.verify,
        }
        if self._settings.token:
            kwargs["token"] = self._settings.token.get_secret_value()
        else:
            kwargs["username"] = self._settings.username
            kwargs["password"] = self._settings.password.get_secret_value()
        return splunk_client.connect(**kwargs)

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
        spl = normalize_spl(query, idx)
        kwargs: dict[str, Any] = {"count": self._clamp_size(size), "output_mode": "json"}
        if earliest:
            kwargs["earliest_time"] = earliest
        if latest:
            kwargs["latest_time"] = latest
        try:
            stream = self.service.jobs.oneshot(spl, **kwargs)
            rows = _read_json_results(stream)
        except Exception as exc:
            raise ToolExecutionError(f"Splunk search failed: {exc}") from exc
        hits = [
            SearchHit(
                id=row.get("_cd"),
                index=row.get("index"),
                timestamp=row.get("_time"),
                source=row,
            )
            for row in rows
        ]
        return SearchResult(
            backend=self.siem_id,
            index=idx,
            total=len(hits),
            returned=len(hits),
            hits=hits,
        )

    def validate_query(self, query: str, *, index: str | None = None) -> QueryValidation:
        idx = index or self.default_index
        spl = normalize_spl(query, idx)
        try:
            self.service.parse(spl, parse_only=True, output_mode="json")
        except Exception as exc:
            return QueryValidation(backend=self.siem_id, valid=False, error=str(exc))
        return QueryValidation(backend=self.siem_id, valid=True)

    def get_fields(self, *, index: str | None = None, limit: int = 200) -> FieldList:
        idx = index or self.default_index
        spl = f"search index={idx} earliest=-24h | fieldsummary maxvals=0 | fields field"
        try:
            stream = self.service.jobs.oneshot(
                spl, count=self._clamp_size(limit), output_mode="json"
            )
            rows = _read_json_results(stream)
        except Exception as exc:
            raise ToolExecutionError(f"Splunk get_fields failed: {exc}") from exc
        fields = [FieldInfo(name=row["field"]) for row in rows if row.get("field")]
        return FieldList(backend=self.siem_id, index=idx, fields=fields[:limit])

    def aggregate_field(
        self,
        field: str,
        *,
        index: str | None = None,
        lookback_days: int = 7,
        top_n: int = 10,
    ) -> FieldAggregation:
        idx = index or self.default_index
        window = f"earliest=-{max(1, lookback_days)}d latest=now"
        limit = max(1, top_n)
        top_spl = (
            f"search index={idx} {window} | stats count by {field} | sort - count | head {limit}"
        )
        totals_spl = f"search index={idx} {window} | stats count as total dc({field}) as distinct"
        try:
            top_rows = _read_json_results(
                self.service.jobs.oneshot(top_spl, count=limit, output_mode="json")
            )
            totals_rows = _read_json_results(
                self.service.jobs.oneshot(totals_spl, count=1, output_mode="json")
            )
        except Exception as exc:
            raise ToolExecutionError(f"Splunk aggregate_field failed: {exc}") from exc
        top_values = [
            {"value": row.get(field), "count": _to_int(row.get("count"))} for row in top_rows
        ]
        totals = totals_rows[0] if totals_rows else {}
        return FieldAggregation(
            backend=self.siem_id,
            field=field,
            index=idx,
            total_events=_to_int(totals.get("total")),
            distinct_values=_to_int(totals.get("distinct")),
            top_values=top_values,
        )

    # -- Saved-search alerts (deploy / disable / delete) --------------------
    def deploy_rule(self, request: DeployRequest) -> DeployResult:
        spl = normalize_spl(request.query, request.index or self.default_index)
        args = splunk_saved_search_args(request)
        try:
            saved = self.service.saved_searches.create(request.name, spl, **args)
        except Exception as exc:
            raise ToolExecutionError(f"Splunk deploy failed: {exc}") from exc
        return DeployResult(
            backend=self.siem_id,
            deploy_id=str(getattr(saved, "name", request.name)),
            name=request.name,
            status="created",
            enabled=request.enabled,
        )

    def disable_rule(self, deploy_id: str) -> DeployResult:
        try:
            self.service.saved_searches[deploy_id].disable()
        except Exception as exc:
            raise ToolExecutionError(f"Splunk disable failed: {exc}") from exc
        return DeployResult(
            backend=self.siem_id,
            deploy_id=deploy_id,
            name=deploy_id,
            status="disabled",
            enabled=False,
        )

    def delete_rule(self, deploy_id: str) -> DeployResult:
        try:
            self.service.saved_searches.delete(deploy_id)
        except Exception as exc:
            raise ToolExecutionError(f"Splunk delete failed: {exc}") from exc
        return DeployResult(
            backend=self.siem_id,
            deploy_id=deploy_id,
            name=deploy_id,
            status="deleted",
            enabled=False,
        )

    def list_alerts(self, *, limit: int = 20) -> AlertList:
        try:
            fired = self.service.fired_alerts
            groups = list(fired)[: max(0, limit)]
            alerts = [
                AlertSummary(
                    id=str(getattr(group, "name", "")),
                    name=str(getattr(group, "name", "")),
                    info={"triggered_alert_count": getattr(group, "count", None)},
                )
                for group in groups
            ]
            total = len(fired)
        except Exception as exc:
            raise ToolExecutionError(f"Splunk list_alerts failed: {exc}") from exc
        return AlertList(backend=self.siem_id, total=total, alerts=alerts)
