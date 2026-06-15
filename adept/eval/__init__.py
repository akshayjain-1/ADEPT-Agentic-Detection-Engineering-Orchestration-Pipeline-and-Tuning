"""ADEPT evaluation harness.

LLM-in-the-loop *scenario* eval that drives the live agent against a routing /
tool-use / content rubric. The rubric scorer is a pure function so it is
unit-tested without a model.
"""

from __future__ import annotations

from adept.eval.models import (
    Scenario,
    ScenarioCheck,
    ScenarioResult,
    ScenarioTrace,
)
from adept.eval.scenarios import DEFAULT_SCENARIOS, run_scenarios, score_scenario

__all__ = [
    "DEFAULT_SCENARIOS",
    "Scenario",
    "ScenarioCheck",
    "ScenarioResult",
    "ScenarioTrace",
    "run_scenarios",
    "score_scenario",
]
