"""Pydantic models for the ADEPT evaluation harness.

* **Scenario eval** (LLM-in-the-loop): natural-language tasks are run against the
  live agent and scored against a rubric of expected routing, tool use, and
  content. ``score_scenario`` is a pure function over a captured trace so the
  rubric itself is unit-testable without a model.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


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
