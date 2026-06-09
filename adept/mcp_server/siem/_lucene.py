"""Shared helpers for the Lucene-based backends (Elasticsearch and OpenSearch).

Elasticsearch and OpenSearch share the same query DSL and response shapes, so
the query builder and response parsers live here and are used by both backends.
Keeping these as pure functions (no live client) makes them directly unit-testable.
"""

from __future__ import annotations

from typing import Any

from adept.mcp_server.siem.models import (
    FieldAggregation,
    FieldInfo,
    FieldList,
    QueryValidation,
    SearchHit,
    SearchResult,
)


def _hits_total(hits_obj: dict[str, Any]) -> int:
    """Extract the hit count from a response's ``hits.total``.

    Elasticsearch/OpenSearch report ``total`` either as an object
    (``{"value": N, "relation": ...}``) or, on older clusters, as a bare integer;
    both shapes are normalised to an ``int``.
    """
    total = hits_obj.get("total")
    if isinstance(total, dict):
        return int(total.get("value", 0) or 0)
    return int(total or 0)


def parse_validate_query_response(resp: Any, *, backend: str) -> QueryValidation:
    """Parse a ``_validate/query?explain`` response into a QueryValidation.

    Shared by the Elasticsearch and OpenSearch backends, whose validate APIs
    return the same ``valid``/``explanations`` shape.
    """
    valid = bool(resp.get("valid"))
    explanations = resp.get("explanations") or []
    detail = None
    if explanations and isinstance(explanations[0], dict):
        detail = explanations[0].get("error")
    return QueryValidation(
        backend=backend,
        valid=valid,
        error=None if valid else (detail or "invalid query"),
        detail=detail,
    )


def lucene_query_string(query: str) -> dict[str, Any]:
    """Build a ``query_string`` clause with leading wildcards disabled.

    A leading wildcard (e.g. ``*foo``) forces Elasticsearch/OpenSearch to expand
    against every term in the index — a cheap denial-of-service vector — so such
    queries are rejected by the engine rather than executed.
    """
    return {"query_string": {"query": query, "allow_leading_wildcard": False}}


def build_lucene_query(
    query: str, earliest: str | None = None, latest: str | None = None
) -> dict[str, Any]:
    """Build a query DSL object from a Lucene string and optional time bounds.

    When a time range is supplied it is applied as a filter on ``@timestamp``
    (the ECS standard timestamp the ADEPT pipelines normalise to).
    """
    query_string = lucene_query_string(query)
    if not (earliest or latest):
        return query_string
    bounds: dict[str, str] = {}
    if earliest:
        bounds["gte"] = earliest
    if latest:
        bounds["lte"] = latest
    return {"bool": {"must": [query_string], "filter": [{"range": {"@timestamp": bounds}}]}}


def build_terms_aggregation(field: str, top_n: int) -> dict[str, Any]:
    """Build the ``terms`` + ``cardinality`` aggregation body for a field."""
    return {
        "top": {"terms": {"field": field, "size": max(1, top_n)}},
        "distinct": {"cardinality": {"field": field}},
    }


def parse_terms_aggregation(resp: Any, *, backend: str, field: str, index: str) -> FieldAggregation:
    """Parse a ``terms``/``cardinality`` aggregation response."""
    hits_obj = resp.get("hits", {}) or {}
    total_value = _hits_total(hits_obj)

    aggs = resp.get("aggregations", {}) or {}
    buckets = (aggs.get("top", {}) or {}).get("buckets", []) or []
    top_values = [
        {"value": bucket.get("key"), "count": int(bucket.get("doc_count", 0) or 0)}
        for bucket in buckets
    ]
    distinct = int((aggs.get("distinct", {}) or {}).get("value", 0) or 0)
    return FieldAggregation(
        backend=backend,
        field=field,
        index=index,
        total_events=total_value,
        distinct_values=distinct,
        top_values=top_values,
    )


def parse_search_response(resp: Any, *, backend: str, index: str) -> SearchResult:
    """Parse an Elasticsearch/OpenSearch ``_search`` response into a SearchResult."""
    hits_obj = resp.get("hits", {}) or {}
    total_value = _hits_total(hits_obj)

    hits: list[SearchHit] = []
    for raw in hits_obj.get("hits", []) or []:
        source = raw.get("_source") or {}
        ts = source.get("@timestamp")
        hits.append(
            SearchHit(
                id=raw.get("_id"),
                index=raw.get("_index"),
                timestamp=str(ts) if ts is not None else None,
                source=source,
            )
        )
    return SearchResult(
        backend=backend,
        index=index,
        total=total_value,
        returned=len(hits),
        took_ms=resp.get("took"),
        hits=hits,
    )


def _flatten_properties(
    properties: dict[str, Any], prefix: str, out: dict[str, str | None]
) -> None:
    """Recursively flatten a mapping's ``properties`` into dotted field names."""
    for name, body in properties.items():
        if not isinstance(body, dict):
            continue
        full = f"{prefix}{name}"
        nested = body.get("properties")
        if isinstance(nested, dict):
            _flatten_properties(nested, f"{full}.", out)
        else:
            out[full] = body.get("type")


def parse_mapping_response(resp: Any, *, backend: str, index: str, limit: int) -> FieldList:
    """Parse a ``get_mapping`` response into a flat, sorted field list."""
    collected: dict[str, str | None] = {}
    for index_body in resp.values():
        if not isinstance(index_body, dict):
            continue
        mappings = index_body.get("mappings") or {}
        properties = mappings.get("properties") or {}
        if isinstance(properties, dict):
            _flatten_properties(properties, "", collected)

    fields = [FieldInfo(name=name, type=collected[name]) for name in sorted(collected)]
    return FieldList(backend=backend, index=index, fields=fields[: max(0, limit)])
