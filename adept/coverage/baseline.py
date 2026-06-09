"""Field baseline profiling for noise / false-positive anticipation.

Given a SIEM backend and a set of fields, profile each field's event volume and
value cardinality over a recent window. High-cardinality fields (whose values
rarely repeat) make poor sole detection filters and tend to generate noisy
alerts; flagging them early helps tune rules before deployment.

The profiler depends only on a backend's ``aggregate_field`` capability, modelled
here as a small :class:`Protocol` so it can be unit-tested with a fake backend.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, Protocol

from adept.coverage.models import BaselineReport, FieldBaseline

if TYPE_CHECKING:
    from adept.mcp_server.siem.models import FieldAggregation

#: Distinct/total ratio at or above which a field's values are deemed to rarely
#: repeat, marking it as noise-prone.
DEFAULT_NOISY_RATIO = 0.5
#: Absolute distinct-value count at or above which a field is always noisy.
DEFAULT_NOISY_DISTINCT = 1000


class AggregatingBackend(Protocol):
    """The single backend capability that baseline profiling depends on."""

    siem_id: ClassVar[str]

    def aggregate_field(
        self,
        field: str,
        *,
        index: str | None = None,
        lookback_days: int = 7,
        top_n: int = 10,
    ) -> FieldAggregation: ...


def _classify(
    agg: FieldAggregation, *, noisy_ratio: float, noisy_distinct: int
) -> tuple[bool, str]:
    """Decide whether a field looks noisy and explain why."""
    if agg.total_events <= 0:
        return False, "no events in window"
    if agg.distinct_values >= noisy_distinct:
        return True, f"high cardinality: {agg.distinct_values} distinct values"
    ratio = agg.distinct_values / agg.total_events
    if ratio >= noisy_ratio:
        return True, (
            f"values rarely repeat ({agg.distinct_values}/{agg.total_events} "
            f"~ {ratio:.0%} distinct)"
        )
    return False, ""


def profile_fields(
    backend: AggregatingBackend,
    fields: Sequence[str],
    *,
    index: str | None = None,
    lookback_days: int = 7,
    top_n: int = 10,
    noisy_ratio: float = DEFAULT_NOISY_RATIO,
    noisy_distinct: int = DEFAULT_NOISY_DISTINCT,
) -> BaselineReport:
    """Profile each field's volume/cardinality and flag noise-prone candidates."""
    baselines: list[FieldBaseline] = []
    for field in fields:
        agg = backend.aggregate_field(field, index=index, lookback_days=lookback_days, top_n=top_n)
        noisy, note = _classify(agg, noisy_ratio=noisy_ratio, noisy_distinct=noisy_distinct)
        baselines.append(
            FieldBaseline(
                field=agg.field,
                total_events=agg.total_events,
                distinct_values=agg.distinct_values,
                top_values=list(agg.top_values),
                noisy=noisy,
                note=note,
            )
        )
    return BaselineReport(
        siem=backend.siem_id,
        index=index or "",
        lookback_days=lookback_days,
        fields=baselines,
    )
