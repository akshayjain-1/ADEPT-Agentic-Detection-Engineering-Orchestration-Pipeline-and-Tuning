"""Historical backtest: estimate a rule's alert volume against real logs.

Converts a Sigma rule to the target SIEM's query language, runs it over the
last *N* days through the SIEM read path, and reports the match count and an
estimated per-day volume. This feeds the human-in-the-loop approval packet so a
reviewer can see how noisy a detection would be before it is deployed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from adept.detection_as_code.converter import SigmaConverter
from adept.detection_as_code.models import BacktestResult
from adept.shared.errors import ValidationFailedError

if TYPE_CHECKING:
    from adept.mcp_server.siem.base import SiemBackend


def backtest_rule(
    rule_text: str,
    backend: SiemBackend,
    *,
    converter: SigmaConverter | None = None,
    index: str | None = None,
    lookback_days: int = 7,
    sample_size: int = 5,
) -> BacktestResult:
    """Backtest ``rule_text`` against ``backend`` over ``lookback_days`` days."""
    if lookback_days < 1:
        raise ValidationFailedError("lookback_days must be >= 1")

    converter = converter or SigmaConverter()
    conversion = converter.convert(rule_text, backend.siem_id, pipelines=None)
    if not conversion.queries:
        raise ValidationFailedError("rule produced no query to backtest")
    # A Sigma rule converts to exactly one query for these query-language
    # backends; use the first and note if there were unexpectedly more.
    query = conversion.queries[0]
    note = (
        ""
        if len(conversion.queries) == 1
        else f"rule produced {len(conversion.queries)} queries; backtested the first"
    )

    earliest = f"now-{lookback_days}d"
    result = backend.search(
        query,
        index=index,
        size=sample_size,
        earliest=earliest,
        latest="now",
    )
    estimated_daily = round(result.total / lookback_days, 2)
    return BacktestResult(
        siem=backend.siem_id,
        query=query,
        lookback_days=lookback_days,
        index=index,
        matches=result.total,
        sampled=len(result.hits) < result.total,
        estimated_daily_volume=estimated_daily,
        note=note,
    )
