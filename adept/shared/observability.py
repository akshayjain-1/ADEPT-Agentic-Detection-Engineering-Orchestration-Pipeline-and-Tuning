"""Lightweight observability scaffolding (tracing + timing).

OpenTelemetry is an *optional* dependency. When it is installed and enabled in
settings, spans are exported via OTLP/HTTP. Otherwise every helper degrades to
a no-op that still records timing to the structured log, so application code can
call these helpers unconditionally.
"""

from __future__ import annotations

import importlib
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from adept.config.settings import OTelSettings
from adept.shared.logging import get_logger

log = get_logger(__name__)

_tracer: Any | None = None


def setup_observability(settings: OTelSettings) -> None:
    """Initialise tracing if enabled and OpenTelemetry is available.

    Safe to call once at process start. Failures degrade to no-op tracing.
    """
    global _tracer
    if not settings.enabled:
        return
    try:
        trace = importlib.import_module("opentelemetry.trace")
        sdk_trace = importlib.import_module("opentelemetry.sdk.trace")
        sdk_export = importlib.import_module("opentelemetry.sdk.trace.export")
        resources = importlib.import_module("opentelemetry.sdk.resources")
        otlp = importlib.import_module("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    except ImportError:
        log.warning(
            "otel_unavailable",
            hint="install the 'observability' extra to enable tracing",
        )
        return

    resource = resources.Resource.create({"service.name": settings.service_name})
    provider = sdk_trace.TracerProvider(resource=resource)
    exporter = otlp.OTLPSpanExporter(endpoint=f"{settings.endpoint}/v1/traces")
    provider.add_span_processor(sdk_export.BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("adept")
    log.info("otel_enabled", endpoint=settings.endpoint)


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[None]:
    """Record a unit of work as a trace span (and a timing log line)."""
    start = time.perf_counter()
    if _tracer is not None:
        with _tracer.start_as_current_span(name) as otel_span:
            for key, value in attributes.items():
                otel_span.set_attribute(key, value)
            yield
    else:
        yield
    duration_ms = (time.perf_counter() - start) * 1000
    log.debug("span", name=name, duration_ms=round(duration_ms, 2), **attributes)
