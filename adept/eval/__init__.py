"""ADEPT evaluation harness.

Two layers: a deterministic, offline *component* eval that scores golden
detection cases with the real Sigma matcher (CI-runnable, no LLM), and an
LLM-in-the-loop *scenario* eval that drives the live agent against a routing /
tool-use / content rubric. The scenario rubric scorer is a pure function so it
is unit-tested without a model.
"""

from __future__ import annotations

from adept.eval.golden import DEFAULT_CASES, evaluate_case, run_component_eval
from adept.eval.models import (
    EvalCaseResult,
    EvalReport,
    GoldenCase,
    Scenario,
    ScenarioCheck,
    ScenarioResult,
    ScenarioTrace,
)
from adept.eval.scenarios import DEFAULT_SCENARIOS, run_scenarios, score_scenario

__all__ = [
    "DEFAULT_CASES",
    "DEFAULT_SCENARIOS",
    "EvalCaseResult",
    "EvalReport",
    "GoldenCase",
    "Scenario",
    "ScenarioCheck",
    "ScenarioResult",
    "ScenarioTrace",
    "evaluate_case",
    "run_component_eval",
    "run_scenarios",
    "score_scenario",
]
