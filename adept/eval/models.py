"""Pydantic models for the ADEPT evaluation harness.

Two evaluation layers share these shapes:

* **Component eval** (offline, CI-runnable): golden ``(rule, events)`` cases are
  scored with the real Sigma matcher into a confusion matrix and
  precision/recall, with no LLM in the loop.
* **Scenario eval** (LLM-in-the-loop): natural-language tasks are run against the
  live agent and scored against a rubric of expected routing, tool use, and
  content. ``score_scenario`` is a pure function over a captured trace so the
  rubric itself is unit-testable without a model.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class GoldenCase(BaseModel):
    """A golden detection case: one rule plus events that must / must not fire."""

    name: str
    technique: str
    rule: str
    positives: list[dict[str, Any]] = Field(default_factory=list)
    negatives: list[dict[str, Any]] = Field(default_factory=list)


class EvalCaseResult(BaseModel):
    """Confusion matrix and scores for a single golden case."""

    name: str
    technique: str
    rule_id: str = ""
    true_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    precision: float = 1.0
    recall: float = 1.0
    f1: float = 1.0
    passed: bool = False


class EvalReport(BaseModel):
    """Aggregate component-eval result across all golden cases."""

    total_cases: int = 0
    passed_cases: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    precision: float = 1.0
    recall: float = 1.0
    f1: float = 1.0
    cases: list[EvalCaseResult] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when every golden case detected all TPs with no FPs."""
        return self.total_cases > 0 and self.passed_cases == self.total_cases


class Scenario(BaseModel):
    """An LLM task plus the rubric its run is scored against."""

    id: str
    prompt: str
    expect_specialists: list[str] = Field(default_factory=list)
    expect_tools: list[str] = Field(default_factory=list)
    forbid_tools: list[str] = Field(default_factory=list)
    must_mention: list[str] = Field(default_factory=list)


class ScenarioTrace(BaseModel):
    """What a scenario run actually did, captured from the agent graph stream."""

    routed_specialists: list[str] = Field(default_factory=list)
    tool_calls: list[str] = Field(default_factory=list)
    final_text: str = ""


class ScenarioCheck(BaseModel):
    """One rubric check applied to a scenario trace."""

    name: str
    passed: bool
    detail: str = ""


class ScenarioResult(BaseModel):
    """Scored outcome of one scenario run."""

    id: str
    passed: bool = False
    score: float = 0.0
    checks: list[ScenarioCheck] = Field(default_factory=list)
