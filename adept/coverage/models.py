"""Pydantic models for ATT&CK coverage analysis.

These describe the outputs of the coverage tools: the technique coverage matrix,
prioritised gaps, rule overlap/duplication, and SIEM field baselines. They are
returned (as ``model_dump`` dicts) by both the ``adept-coverage`` CLI and the
MCP coverage tools.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Priority = Literal["high", "medium", "low"]


class TechniqueCoverage(BaseModel):
    """How many local rules map to a single ATT&CK technique."""

    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    rule_count: int = 0
    rule_ids: list[str] = Field(default_factory=list)
    rule_titles: list[str] = Field(default_factory=list)


class CoverageMatrix(BaseModel):
    """ATT&CK coverage derived from the local Sigma ruleset."""

    domain: str = "enterprise-attack"
    total_techniques: int = 0
    covered_techniques: int = 0
    coverage_pct: float = 0.0
    techniques: list[TechniqueCoverage] = Field(default_factory=list)
    untagged_rules: list[str] = Field(default_factory=list)


class CoverageGap(BaseModel):
    """An ATT&CK technique with no local detection coverage."""

    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    priority: Priority = "medium"
    reasons: list[str] = Field(default_factory=list)


class GapReport(BaseModel):
    """Prioritised list of uncovered techniques within a scope."""

    scope: dict[str, list[str]] = Field(default_factory=dict)
    total_in_scope: int = 0
    covered_in_scope: int = 0
    total_gaps: int = 0
    gaps: list[CoverageGap] = Field(default_factory=list)


class OverlapPair(BaseModel):
    """Two rules that may be redundant with one another."""

    rule_a: str
    rule_b: str
    shared_techniques: list[str] = Field(default_factory=list)
    field_similarity: float = 0.0
    reasons: list[str] = Field(default_factory=list)


class OverlapReport(BaseModel):
    """Candidate duplicate/overlapping rules in the local ruleset."""

    total: int = 0
    pairs: list[OverlapPair] = Field(default_factory=list)


class FieldBaseline(BaseModel):
    """Volume/cardinality profile of a single field over recent logs."""

    field: str
    total_events: int = 0
    distinct_values: int = 0
    top_values: list[dict[str, object]] = Field(default_factory=list)
    noisy: bool = False
    note: str = ""


class BaselineReport(BaseModel):
    """Field baselines used to anticipate noisy detections."""

    siem: str
    index: str = ""
    lookback_days: int = 7
    fields: list[FieldBaseline] = Field(default_factory=list)
