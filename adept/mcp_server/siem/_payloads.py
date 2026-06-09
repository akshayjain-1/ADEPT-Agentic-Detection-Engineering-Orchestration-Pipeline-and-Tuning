"""Pure builders for SIEM detection-deployment payloads.

The request bodies for each platform's management API are constructed here as
pure functions so they can be unit-tested without any live SIEM. The shapes were
taken from the official documentation:

- Kibana Detection Engine: ``POST /api/detection_engine/rules`` (custom ``query``
  rule with ``language: lucene``). Required fields: name, description, risk_score,
  severity, type, query, language.
- OpenSearch Alerting: ``POST /_plugins/_alerting/monitors`` (``query_level_monitor``
  with a painless trigger on ``ctx.results[0].hits.total.value``).
- Splunk: a scheduled saved-search alert created via ``splunklib``
  ``saved_searches.create`` with the standard ``alert_*`` attributes.
"""

from __future__ import annotations

from typing import Any

from adept.mcp_server.siem.models import DeployRequest, Severity

#: Kibana risk_score bands (0-21 low, 22-47 medium, 48-73 high, 74-100 critical).
KIBANA_RISK_SCORE: dict[Severity, int] = {
    "low": 21,
    "medium": 47,
    "high": 73,
    "critical": 99,
}

#: OpenSearch alerting trigger severity ("1" is the highest, "5" the lowest).
OPENSEARCH_SEVERITY: dict[Severity, str] = {
    "critical": "1",
    "high": "2",
    "medium": "3",
    "low": "4",
}


def kibana_rule_payload(req: DeployRequest) -> dict[str, Any]:
    """Build the body for a Kibana ``query``-type detection rule (Lucene)."""
    payload: dict[str, Any] = {
        "name": req.name,
        "description": req.description or req.name,
        "rule_id": req.rule_id,
        "type": "query",
        "language": "lucene",
        "query": req.query,
        "risk_score": KIBANA_RISK_SCORE[req.severity],
        "severity": req.severity,
        "enabled": req.enabled,
        "interval": f"{req.interval_minutes}m",
        "from": f"now-{req.lookback_minutes}m",
        "to": "now",
        "tags": req.tags,
    }
    if req.index:
        payload["index"] = [req.index]
    return payload


def opensearch_monitor_payload(req: DeployRequest) -> dict[str, Any]:
    """Build the body for an OpenSearch ``query_level_monitor``."""
    # ``{{period_end}}`` is an Alerting template variable resolved at run time;
    # built with concatenation to keep the literal double braces intact.
    gte = "{{period_end}}||-" + str(req.lookback_minutes) + "m"
    search_query: dict[str, Any] = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte,
                                "lte": "{{period_end}}",
                                "format": "epoch_millis",
                            }
                        }
                    },
                    {"query_string": {"query": req.query}},
                ]
            }
        },
    }
    return {
        "type": "monitor",
        "name": req.name,
        "monitor_type": "query_level_monitor",
        "enabled": req.enabled,
        "schedule": {"period": {"interval": req.interval_minutes, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": [req.index or "*"], "query": search_query}}],
        "triggers": [
            {
                "name": f"{req.name}-trigger",
                "severity": OPENSEARCH_SEVERITY[req.severity],
                "condition": {
                    "script": {
                        "source": "ctx.results[0].hits.total.value > 0",
                        "lang": "painless",
                    }
                },
                "actions": [],
            }
        ],
    }


def splunk_saved_search_args(req: DeployRequest) -> dict[str, Any]:
    """Build the keyword attributes for a Splunk scheduled saved-search alert.

    The returned mapping excludes ``name`` and ``search`` (passed positionally to
    ``saved_searches.create``).
    """
    return {
        "is_scheduled": True,
        "cron_schedule": f"*/{req.interval_minutes} * * * *",
        "dispatch.earliest_time": f"-{req.lookback_minutes}m",
        "dispatch.latest_time": "now",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": 1,
        "description": req.description or req.name,
        "disabled": 0 if req.enabled else 1,
    }
