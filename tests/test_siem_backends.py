"""Tests for the multi-SIEM read backends, using injected fake clients."""

from __future__ import annotations

from typing import Any

from adept.config.settings import ELKSettings, OpenSearchSettings, Settings
from adept.mcp_server.siem._lucene import (
    build_lucene_query,
    lucene_query_string,
    parse_mapping_response,
    parse_search_response,
)
from adept.mcp_server.siem._payloads import (
    KIBANA_RISK_SCORE,
    kibana_rule_payload,
    opensearch_monitor_payload,
    splunk_saved_search_args,
)
from adept.mcp_server.siem.elk import ELKBackend
from adept.mcp_server.siem.models import DeployRequest
from adept.mcp_server.siem.opensearch import OpenSearchBackend
from adept.mcp_server.siem.registry import build_backends
from adept.mcp_server.siem.splunk import normalize_spl

ES_SEARCH: dict[str, Any] = {
    "took": 7,
    "hits": {
        "total": {"value": 2},
        "hits": [
            {
                "_id": "1",
                "_index": "logs-a",
                "_source": {"@timestamp": "2024-01-01T00:00:00Z", "message": "hi"},
            },
            {"_id": "2", "_index": "logs-a", "_source": {"message": "yo"}},
        ],
    },
}

ES_MAPPING: dict[str, Any] = {
    "logs-a": {
        "mappings": {
            "properties": {
                "message": {"type": "text"},
                "@timestamp": {"type": "date"},
                "process": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "pid": {"type": "long"},
                    }
                },
            }
        }
    }
}


class _FakeIndices:
    def __init__(self, mapping: dict[str, Any], validate: dict[str, Any]) -> None:
        self._mapping = mapping
        self._validate = validate

    def validate_query(self, **_kwargs: Any) -> dict[str, Any]:
        return self._validate

    def get_mapping(self, **_kwargs: Any) -> dict[str, Any]:
        return self._mapping


class _FakeClient:
    def __init__(
        self,
        search_resp: dict[str, Any],
        mapping: dict[str, Any],
        validate: dict[str, Any],
    ) -> None:
        self._search = search_resp
        self.indices = _FakeIndices(mapping, validate)

    def search(self, **_kwargs: Any) -> dict[str, Any]:
        return self._search


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def test_build_lucene_query_plain() -> None:
    assert build_lucene_query("foo:bar") == {
        "query_string": {"query": "foo:bar", "allow_leading_wildcard": False}
    }


def test_lucene_query_string_disables_leading_wildcards() -> None:
    # Leading wildcards (``*foo``) are a cluster DoS vector and must be disabled
    # wherever a raw Lucene string is handed to the engine.
    assert lucene_query_string("*foo")["query_string"]["allow_leading_wildcard"] is False
    assert build_lucene_query("*foo")["query_string"]["allow_leading_wildcard"] is False


def test_build_lucene_query_with_time_range() -> None:
    built = build_lucene_query("foo:bar", earliest="2024-01-01", latest="2024-01-02")
    range_filter = built["bool"]["filter"][0]["range"]["@timestamp"]
    assert range_filter == {"gte": "2024-01-01", "lte": "2024-01-02"}


def test_parse_search_response() -> None:
    result = parse_search_response(ES_SEARCH, backend="elk", index="logs-a")
    assert result.total == 2
    assert result.returned == 2
    assert result.took_ms == 7
    assert result.hits[0].timestamp == "2024-01-01T00:00:00Z"
    assert result.hits[1].timestamp is None


def test_parse_mapping_response_flattens_nested() -> None:
    field_list = parse_mapping_response(ES_MAPPING, backend="elk", index="logs-a", limit=100)
    names = {f.name for f in field_list.fields}
    assert {"message", "@timestamp", "process.name", "process.pid"} <= names


def test_normalize_spl_wraps_bare_query() -> None:
    assert (
        normalize_spl("EventCode=4688", "wineventlog") == "search index=wineventlog EventCode=4688"
    )


def test_normalize_spl_leaves_search_and_pipe() -> None:
    assert normalize_spl("search foo", "idx") == "search foo"
    assert normalize_spl("| tstats count", "idx") == "| tstats count"


# ---------------------------------------------------------------------------
# Backends with injected fake clients
# ---------------------------------------------------------------------------
def test_elk_backend_search() -> None:
    client = _FakeClient(ES_SEARCH, ES_MAPPING, {"valid": True})
    backend = ELKBackend(ELKSettings(), client=client)
    result = backend.search("message:hi", size=10)
    assert result.backend == "elk"
    assert result.returned == 2


def test_elk_backend_validate_valid() -> None:
    client = _FakeClient(ES_SEARCH, ES_MAPPING, {"valid": True})
    backend = ELKBackend(ELKSettings(), client=client)
    assert backend.validate_query("message:hi").valid is True


def test_elk_backend_validate_invalid() -> None:
    invalid = {"valid": False, "explanations": [{"index": "logs-a", "error": "boom"}]}
    client = _FakeClient(ES_SEARCH, ES_MAPPING, invalid)
    backend = ELKBackend(ELKSettings(), client=client)
    validation = backend.validate_query("bad:::query")
    assert validation.valid is False
    assert validation.detail == "boom"


def test_elk_backend_get_fields() -> None:
    client = _FakeClient(ES_SEARCH, ES_MAPPING, {"valid": True})
    backend = ELKBackend(ELKSettings(), client=client)
    names = {f.name for f in backend.get_fields().fields}
    assert "process.pid" in names


def test_opensearch_backend_search() -> None:
    client = _FakeClient(ES_SEARCH, ES_MAPPING, {"valid": True})
    backend = OpenSearchBackend(OpenSearchSettings(), client=client)
    result = backend.search("message:hi")
    assert result.backend == "opensearch"
    assert result.returned == 2


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def test_build_backends_honours_enabled_flags() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.elk.enabled = True
    settings.opensearch.enabled = True
    settings.splunk.enabled = True
    backends = build_backends(settings)
    assert set(backends) == {"elk", "opensearch", "splunk"}
    assert backends["splunk"].siem_id == "splunk"


def test_build_backends_skips_disabled() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.elk.enabled = False
    settings.opensearch.enabled = False
    settings.splunk.enabled = False
    assert build_backends(settings) == {}


# ---------------------------------------------------------------------------
# Deploy payload builders (the documented-API surface)
# ---------------------------------------------------------------------------
def _deploy_request() -> DeployRequest:
    return DeployRequest(
        rule_id="75aab411-6c19-466c-81a7-c3ababbdc340",
        name="Whoami discovery",
        query="Image:*whoami.exe",
        index="logs-*",
        description="Detects whoami execution",
        severity="high",
        interval_minutes=10,
        lookback_minutes=15,
    )


def test_kibana_rule_payload_shape() -> None:
    payload = kibana_rule_payload(_deploy_request())
    assert payload["type"] == "query"
    assert payload["language"] == "lucene"
    assert payload["query"] == "Image:*whoami.exe"
    assert payload["risk_score"] == KIBANA_RISK_SCORE["high"]
    assert payload["severity"] == "high"
    assert payload["interval"] == "10m"
    assert payload["from"] == "now-15m"
    assert payload["index"] == ["logs-*"]
    assert payload["rule_id"] == "75aab411-6c19-466c-81a7-c3ababbdc340"


def test_opensearch_monitor_payload_shape() -> None:
    payload = opensearch_monitor_payload(_deploy_request())
    assert payload["monitor_type"] == "query_level_monitor"
    assert payload["schedule"]["period"] == {"interval": 10, "unit": "MINUTES"}
    search = payload["inputs"][0]["search"]
    assert search["indices"] == ["logs-*"]
    filters = search["query"]["query"]["bool"]["filter"]
    assert {"query_string": {"query": "Image:*whoami.exe"}} in filters
    assert "{{period_end}}||-15m" in filters[0]["range"]["@timestamp"]["gte"]
    trigger = payload["triggers"][0]
    assert trigger["condition"]["script"]["source"] == "ctx.results[0].hits.total.value > 0"
    assert trigger["severity"] == "2"


def test_splunk_saved_search_args_shape() -> None:
    args = splunk_saved_search_args(_deploy_request())
    assert args["is_scheduled"] is True
    assert args["cron_schedule"] == "*/10 * * * *"
    assert args["dispatch.earliest_time"] == "-15m"
    assert args["alert_type"] == "number of events"
    assert args["alert_comparator"] == "greater than"
    assert args["alert_threshold"] == "0"
    assert args["disabled"] == 0
    assert "search" not in args


def test_elk_deploy_without_kibana_url_raises() -> None:
    backend = ELKBackend(ELKSettings(kibana_url=""))
    try:
        backend.deploy_rule(_deploy_request())
    except Exception as exc:  # ConfigurationError is an AdeptError
        assert "KIBANA_URL" in str(exc)
    else:  # pragma: no cover - must raise
        raise AssertionError("expected deploy to fail without a Kibana URL")
