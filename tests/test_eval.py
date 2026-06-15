"""Offline tests for the evaluation harness.

The scenario rubric scorer is pure, so it is exercised here with synthetic
traces; the live ``run_scenarios`` path requires Ollama + MCP and is not tested
in CI.
"""

from __future__ import annotations

from adept.eval.models import Scenario, ScenarioTrace
from adept.eval.scenarios import DEFAULT_SCENARIOS, score_scenariodef test_score_scenario_all_checks_pass() -> None:
    scenario = Scenario(
        id="s1",
        prompt="write a rule",
        expect_specialists=["rule_author"],
        expect_tools=["write_sigma_rule"],
        forbid_tools=["siem_deploy_rule"],
        must_mention=["sigma"],
    )
    trace = ScenarioTrace(
        routed_specialists=["rule_author"],
        tool_calls=["write_sigma_rule", "validate_sigma_rule"],
        final_text="Here is the Sigma rule you asked for.",
    )
    result = score_scenario(scenario, trace)
    assert result.passed
    assert result.score == 1.0
    assert all(check.passed for check in result.checks)


def test_score_scenario_detects_each_failure() -> None:
    scenario = Scenario(
        id="s2",
        prompt="write a rule but do not deploy",
        expect_specialists=["rule_author"],
        expect_tools=["write_sigma_rule"],
        forbid_tools=["siem_deploy_rule"],
        must_mention=["backtest"],
    )
    trace = ScenarioTrace(
        routed_specialists=["deployment_operator"],
        tool_calls=["siem_deploy_rule"],
        final_text="Deployed.",
    )
    result = score_scenario(scenario, trace)
    assert not result.passed
    assert result.score == 0.0
    failed = {check.name for check in result.checks if not check.passed}
    assert failed == {"routing", "tools_used", "no_forbidden_tools", "mentions"}


def test_score_scenario_with_no_rubric_passes() -> None:
    scenario = Scenario(id="empty", prompt="hello")
    result = score_scenario(scenario, ScenarioTrace())
    assert result.passed
    assert result.score == 1.0
    assert result.checks == []


def test_default_scenarios_are_internally_consistent() -> None:
    seen_ids: set[str] = set()
    for scenario in DEFAULT_SCENARIOS:
        assert scenario.id not in seen_ids
        seen_ids.add(scenario.id)
        assert scenario.prompt.strip()
        # A forbidden tool must never also be an expected tool.
        assert not (set(scenario.expect_tools) & set(scenario.forbid_tools))
