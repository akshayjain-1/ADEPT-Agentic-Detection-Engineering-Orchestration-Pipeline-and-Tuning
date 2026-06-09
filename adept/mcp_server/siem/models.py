"""Pydantic models for SIEM tool inputs and outputs.

These are the structured payloads returned by the multi-SIEM tools so the agent
(and the human reviewer) receive consistent, typed results regardless of which
backend served the request.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SearchHit(BaseModel):
    """A single document/event returned by a SIEM search."""

    id: str | None = None
    index: str | None = None
    timestamp: str | None = None
    source: dict[str, Any] = Field(default_factory=dict)


class SearchResult(BaseModel):
    """The outcome of a search against one SIEM backend."""

    backend: str
    index: str
    total: int = 0
    returned: int = 0
    took_ms: int | None = None
    hits: list[SearchHit] = Field(default_factory=list)


class QueryValidation(BaseModel):
    """Whether a query is syntactically valid for a backend."""

    backend: str
    valid: bool
    error: str | None = None
    detail: str | None = None


class FieldInfo(BaseModel):
    """A single field discovered in an index mapping."""

    name: str
    type: str | None = None


class FieldList(BaseModel):
    """The fields available in an index, for query authoring."""

    backend: str
    index: str
    fields: list[FieldInfo] = Field(default_factory=list)


class FieldAggregation(BaseModel):
    """Volume/cardinality aggregation of a single field over a time window."""

    backend: str
    field: str
    index: str = ""
    total_events: int = 0
    distinct_values: int = 0
    top_values: list[dict[str, Any]] = Field(default_factory=list)


Severity = Literal["low", "medium", "high", "critical"]


class DeployRequest(BaseModel):
    """A request to deploy a detection to a SIEM.

    ``query`` must already be converted to the target backend's query language
    (Lucene for ELK/OpenSearch, SPL for Splunk). Deployment is a state-changing
    operation and is expected to run only after the human approval gate.
    """

    rule_id: str
    name: str
    query: str
    index: str | None = None
    description: str = ""
    severity: Severity = "medium"
    interval_minutes: int = Field(default=5, ge=1, le=1440)
    lookback_minutes: int = Field(default=5, ge=1, le=10080)
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)


class DeployResult(BaseModel):
    """The outcome of a deploy / disable / delete operation."""

    backend: str
    deploy_id: str
    name: str
    status: Literal["created", "updated", "disabled", "deleted"]
    enabled: bool
    detail: str | None = None


class AlertSummary(BaseModel):
    """A single triggered alert from a SIEM."""

    id: str | None = None
    name: str | None = None
    severity: str | None = None
    state: str | None = None
    triggered_at: str | None = None
    info: dict[str, Any] = Field(default_factory=dict)


class AlertList(BaseModel):
    """Recently triggered alerts from a SIEM backend."""

    backend: str
    total: int = 0
    alerts: list[AlertSummary] = Field(default_factory=list)
