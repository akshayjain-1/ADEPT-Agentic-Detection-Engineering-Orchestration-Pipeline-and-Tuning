"""LLM-in-the-loop scenario evaluation.

A :class:`Scenario` is a natural-language task plus a rubric: which specialists
should be routed to, which tools should (and must not) be called, and which
strings the final answer should mention. :func:`score_scenario` is a *pure*
function over a captured :class:`ScenarioTrace`, so the rubric is unit-tested
without a model. :func:`run_scenarios` drives the live agent (Ollama + MCP) and
auto-rejects every approval gate, so evaluation never executes a destructive
tool — only the agent's *intent* (the emitted tool call) is scored.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from adept.eval.models import Scenario, ScenarioCheck, ScenarioResult, ScenarioTrace

if TYPE_CHECKING:
    from adept.agent.service import AgentSession


def score_scenario(scenario: Scenario, trace: ScenarioTrace) -> ScenarioResult:
    """Score a captured trace against a scenario's rubric (pure)."""
    checks: list[ScenarioCheck] = []
    routed = set(trace.routed_specialists)
    called = set(trace.tool_calls)
    final = trace.final_text.lower()

    if scenario.expect_specialists:
        missing = [s for s in scenario.expect_specialists if s not in routed]
        checks.append(
            ScenarioCheck(
                name="routing",
                passed=not missing,
                detail="" if not missing else f"never routed to: {', '.join(missing)}",
            )
        )
    if scenario.expect_tools:
        missing_tools = [t for t in scenario.expect_tools if t not in called]
        checks.append(
            ScenarioCheck(
                name="tools_used",
                passed=not missing_tools,
                detail=""
                if not missing_tools
                else f"missing tool calls: {', '.join(missing_tools)}",
            )
        )
    if scenario.forbid_tools:
        used_forbidden = [t for t in scenario.forbid_tools if t in called]
        checks.append(
            ScenarioCheck(
                name="no_forbidden_tools",
                passed=not used_forbidden,
                detail=""
                if not used_forbidden
                else f"called forbidden: {', '.join(used_forbidden)}",
            )
        )
    if scenario.must_mention:
        missing_mentions = [m for m in scenario.must_mention if m.lower() not in final]
        checks.append(
            ScenarioCheck(
                name="mentions",
                passed=not missing_mentions,
                detail=""
                if not missing_mentions
                else f"answer omitted: {', '.join(missing_mentions)}",
            )
        )

    passed_checks = sum(1 for check in checks if check.passed)
    score = 1.0 if not checks else round(passed_checks / len(checks), 4)
    return ScenarioResult(
        id=scenario.id,
        passed=all(check.passed for check in checks),
        score=score,
        checks=checks,
    )


# A representative rubric covering routing, tool selection, the approval gate,
# and the propose-only purple-team loop. Tune per deployment.
DEFAULT_SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="author_powershell_rule",
        prompt=(
            "Write a Sigma rule that detects PowerShell encoded commands "
            "(T1059.001), validate it, and backtest it. Do not deploy it."
        ),
        expect_specialists=["rule_author"],
        expect_tools=["write_sigma_rule", "validate_sigma_rule"],
        forbid_tools=["siem_deploy_rule"],
        must_mention=["sigma"],
    ),
    Scenario(
        id="coverage_gaps",
        prompt="What are my top MITRE ATT&CK detection coverage gaps right now?",
        expect_specialists=["coverage_strategist"],
        expect_tools=["identify_coverage_gaps"],
    ),
    Scenario(
        id="intel_lookup",
        prompt="Look up CVE-2021-44228 and tell me whether it is known to be exploited.",
        expect_specialists=["hunt_analyst"],
        expect_tools=["lookup_cve"],
        must_mention=["CVE-2021-44228"],
    ),
    Scenario(
        id="purple_team_propose",
        prompt=(
            "Simulate T1059.001 with Atomic Red Team and tell me what telemetry "
            "to expect. Do not run anything yourself."
        ),
        expect_specialists=["purple_team"],
        expect_tools=["plan_atomic_test"],
        must_mention=["T1059.001"],
    ),
)


def _absorb_update(update: dict[str, Any], trace: ScenarioTrace, specialists: set[str]) -> None:
    """Fold one ``stream_mode='updates'`` chunk into the running trace."""
    from adept.agent.supervisor import message_text

    for node, value in update.items():
        if node in specialists:
            trace.routed_specialists.append(node)
        if not isinstance(value, dict):
            continue
        for message in value.get("messages", []) or []:
            for tool_call in getattr(message, "tool_calls", None) or []:
                name = tool_call.get("name") if isinstance(tool_call, dict) else None
                if name:
                    trace.tool_calls.append(str(name))
            text = message_text(message)
            if text.strip():
                trace.final_text = text


async def run_scenarios(
    session: AgentSession,
    scenarios: Sequence[Scenario] = DEFAULT_SCENARIOS,
    *,
    thread_prefix: str = "eval",
) -> list[ScenarioResult]:
    """Run scenarios against the live agent and score each one.

    Every human-approval interrupt is auto-rejected, so dangerous tools are
    never executed — only the emitted tool call (the agent's intent) is scored.
    Requires a reachable Ollama model and MCP server; not run in CI.
    """
    from langchain_core.messages import HumanMessage
    from langgraph.types import Command

    from adept.agent.approval import ApprovalDecision
    from adept.agent.specialists import SPECIALISTS

    specialist_names = {spec.name for spec in SPECIALISTS}
    reject = ApprovalDecision(action="reject", feedback="eval: auto-rejected").model_dump()
    results: list[ScenarioResult] = []

    for scenario in scenarios:
        config: dict[str, Any] = {
            "configurable": {"thread_id": f"{thread_prefix}-{scenario.id}"},
            "recursion_limit": session.settings.agent.recursion_limit,
        }
        trace = ScenarioTrace()
        payload: Any = {"messages": [HumanMessage(content=scenario.prompt)]}
        while True:
            interrupted = False
            async for update in session.app.astream(payload, config, stream_mode="updates"):
                if "__interrupt__" in update:
                    interrupted = True
                _absorb_update(update, trace, specialist_names)
            if not interrupted:
                break
            payload = Command(resume=reject)
        results.append(score_scenario(scenario, trace))

    return results
