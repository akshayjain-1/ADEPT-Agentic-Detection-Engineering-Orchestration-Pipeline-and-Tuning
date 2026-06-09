"""Pydantic result models for the detection-as-code pipeline.

These are returned by the converter, validator, unit-test harness and backtest
runner, and are also serialised by the MCP tool layer (``model_dump()``).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

IssueSeverity = Literal["low", "medium", "high"]
LifecycleStage = Literal["draft", "testing", "production", "deprecated", "disabled"]


class ConversionResult(BaseModel):
    """Outcome of converting a single Sigma rule to a SIEM query language."""

    siem: str
    target: str
    query_language: str
    pipelines: list[str] = Field(default_factory=list)
    queries: list[str] = Field(default_factory=list)


class ValidationIssue(BaseModel):
    """A single problem reported by the Sigma validators."""

    check: str
    severity: IssueSeverity
    message: str
    rule_ids: list[str] = Field(default_factory=list)


class ValidationReport(BaseModel):
    """Aggregated validation result for one or more rules."""

    ok: bool
    rule_count: int
    issues: list[ValidationIssue] = Field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "high")


class UnitTestCaseResult(BaseModel):
    """Result for a single true/false-positive sample event."""

    name: str
    kind: Literal["true_positive", "false_positive"]
    expected_match: bool
    actual_match: bool
    passed: bool


class UnitTestReport(BaseModel):
    """Result of running the TP/FP sample-event tests for a rule."""

    rule: str
    rule_id: str
    ok: bool
    total: int
    passed: int
    failed: int
    cases: list[UnitTestCaseResult] = Field(default_factory=list)


class BacktestResult(BaseModel):
    """Outcome of replaying a converted rule against historical SIEM data."""

    siem: str
    query: str
    lookback_days: int
    index: str | None = None
    matches: int
    sampled: bool
    estimated_daily_volume: float
    note: str = ""
