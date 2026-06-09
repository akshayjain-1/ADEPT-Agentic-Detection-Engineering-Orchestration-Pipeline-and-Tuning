"""Offline tests for the LangGraph multi-agent layer.

These tests never touch Ollama or a live MCP server. A deterministic
``ScriptedModel`` replays canned assistant messages (including tool calls) so the
supervisor graph, the specialists built with ``create_agent`` and the
human-in-the-loop approval gate can be exercised end-to-end with an in-memory
checkpointer.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

import httpx
import pytest
from adept.agent.approval import (
    ApprovalDecision,
    ApprovalRequest,
    derive_guarded_tool_names,
    guard_tools,
)
from adept.agent.audit import AuditLog
from adept.agent.cli import _parse_mention
from adept.agent.history import list_threads, new_thread_id
from adept.agent.llm import build_chat_model
from adept.agent.service import AgentSession, ProgressEvent
from adept.agent.specialists import DEPLOYMENT_OPERATOR, SPECIALISTS, SpecialistSpec
from adept.agent.supervisor import (
    FINISH,
    _parse_choice,
    _routing_digest,
    build_supervisor_graph,
    message_text,
)
from adept.config.settings import Settings
from adept.shared.errors import ModelTimeoutError
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool, ToolException
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Chat-model factory
# ---------------------------------------------------------------------------
def test_build_chat_model_wires_request_timeout() -> None:
    # The Ollama request timeout must reach the client so a stalled generation
    # cannot hang a turn forever (regression guard for the timeout wiring).
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    model = build_chat_model(settings)
    assert model.client_kwargs == {"timeout": settings.ollama.request_timeout}


# ---------------------------------------------------------------------------
# Offline fakes
# ---------------------------------------------------------------------------


class ScriptedModel(BaseChatModel):
    """A chat model that replays a fixed list of messages, one per call.

    ``bind_tools`` returns ``self`` so the model can drive ``create_agent``
    specialists. The final scripted message is repeated if the graph makes more
    calls than were scripted.
    """

    responses: list[BaseMessage]
    index: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **kwargs: Any) -> ScriptedModel:
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        message = self.responses[min(self.index, len(self.responses) - 1)]
        self.index += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


class _DeployArgs(BaseModel):
    rule_id: str


class _SearchArgs(BaseModel):
    query: str


def _make_deploy_tool(executed: list[str]) -> StructuredTool:
    async def _deploy(rule_id: str) -> str:
        executed.append(rule_id)
        return f"DEPLOYED {rule_id}"

    return StructuredTool.from_function(
        coroutine=_deploy,
        name="siem_deploy_rule",
        description="Deploy a detection rule to the SIEM.",
        args_schema=_DeployArgs,
        infer_schema=False,
    )


def _make_search_tool() -> StructuredTool:
    async def _search(query: str) -> str:
        return "no results"

    return StructuredTool.from_function(
        coroutine=_search,
        name="siem_search",
        description="Search the SIEM (read-only).",
        args_schema=_SearchArgs,
        infer_schema=False,
    )


def _deploy_script() -> list[BaseMessage]:
    """Route to the deployment operator, call the deploy tool, then finish."""
    return [
        AIMessage(content="deployment_operator"),
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "siem_deploy_rule",
                    "args": {"rule_id": "r1"},
                    "id": "call-1",
                    "type": "tool_call",
                }
            ],
        ),
        AIMessage(content="Deployment complete."),
        AIMessage(content="FINISH"),
    ]


def _build_deploy_graph(audit: AuditLog, tool: StructuredTool) -> Any:
    model = ScriptedModel(responses=_deploy_script())
    return build_supervisor_graph(
        model,
        [tool],
        audit=audit,
        dangerous={"siem_deploy_rule"},
        specialists=(DEPLOYMENT_OPERATOR,),
        checkpointer=InMemorySaver(),
    )


async def _run_to_interrupt(graph: Any, thread_id: str) -> dict[str, Any]:
    config = {"configurable": {"thread_id": thread_id}}
    result = await graph.ainvoke({"messages": [HumanMessage(content="deploy rule r1")]}, config)
    assert "__interrupt__" in result
    return result


# ---------------------------------------------------------------------------
# Human-in-the-loop approval gate (end-to-end through the supervisor graph)
# ---------------------------------------------------------------------------


async def test_hitl_approve_executes_tool(tmp_path: Path) -> None:
    executed: list[str] = []
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _build_deploy_graph(audit, _make_deploy_tool(executed))
    config = {"configurable": {"thread_id": "t-approve"}}

    paused = await _run_to_interrupt(graph, "t-approve")
    request = ApprovalRequest.model_validate(paused["__interrupt__"][0].value)
    assert request.tool == "siem_deploy_rule"
    assert request.arguments == {"rule_id": "r1"}

    decision = ApprovalDecision(action="approve")
    result = await graph.ainvoke(Command(resume=decision.model_dump()), config)

    assert "__interrupt__" not in result
    assert executed == ["r1"]
    texts = [message_text(m) for m in result["messages"]]
    assert any("DEPLOYED r1" in text for text in texts)

    events = [entry["event"] for entry in audit.entries()]
    assert events.count("approval_decision") == 1
    assert "tool_executed" in events


async def test_hitl_reject_skips_tool(tmp_path: Path) -> None:
    executed: list[str] = []
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _build_deploy_graph(audit, _make_deploy_tool(executed))
    config = {"configurable": {"thread_id": "t-reject"}}

    await _run_to_interrupt(graph, "t-reject")
    result = await graph.ainvoke(
        Command(resume=ApprovalDecision(action="reject").model_dump()), config
    )

    assert "__interrupt__" not in result
    assert executed == []
    events = [entry["event"] for entry in audit.entries()]
    assert "approval_decision" in events
    assert "tool_executed" not in events


async def test_hitl_edit_changes_arguments(tmp_path: Path) -> None:
    executed: list[str] = []
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _build_deploy_graph(audit, _make_deploy_tool(executed))
    config = {"configurable": {"thread_id": "t-edit"}}

    await _run_to_interrupt(graph, "t-edit")
    decision = ApprovalDecision(action="edit", edited_arguments={"rule_id": "r2"})
    result = await graph.ainvoke(Command(resume=decision.model_dump()), config)

    assert "__interrupt__" not in result
    assert executed == ["r2"]
    texts = [message_text(m) for m in result["messages"]]
    assert any("DEPLOYED r2" in text for text in texts)
    executed_entry = next(e for e in audit.entries() if e["event"] == "tool_executed")
    assert executed_entry["arguments"] == {"rule_id": "r2"}


async def test_hitl_request_changes_returns_feedback(tmp_path: Path) -> None:
    executed: list[str] = []
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _build_deploy_graph(audit, _make_deploy_tool(executed))
    config = {"configurable": {"thread_id": "t-rc"}}

    await _run_to_interrupt(graph, "t-rc")
    decision = ApprovalDecision(
        action="request_changes", feedback="Use rule r2 and narrow the query."
    )
    result = await graph.ainvoke(Command(resume=decision.model_dump()), config)

    assert "__interrupt__" not in result
    assert executed == []
    texts = [message_text(m) for m in result["messages"]]
    assert any("Use rule r2" in text for text in texts)


# ---------------------------------------------------------------------------
# Tool guarding and graph assembly
# ---------------------------------------------------------------------------


def test_guard_tools_wraps_only_dangerous(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    deploy = _make_deploy_tool([])
    search = _make_search_tool()

    wrapped = guard_tools([deploy, search], {"siem_deploy_rule"}, audit=audit)
    by_name = {tool.name: tool for tool in wrapped}

    assert by_name["siem_deploy_rule"] is not deploy
    assert by_name["siem_search"] is search
    assert by_name["siem_deploy_rule"].args_schema is deploy.args_schema


def _annotated_tool(name: str, metadata: dict[str, object] | None) -> StructuredTool:
    async def _run() -> str:
        return "ok"

    return StructuredTool.from_function(
        coroutine=_run,
        name=name,
        description=name,
        metadata=metadata,
    )


def test_derive_guarded_tool_names_is_fail_safe_default_deny() -> None:
    # The gate is derived from the server's MCP annotations: read-only and
    # explicitly non-destructive writes pass freely, while destructive *and*
    # unannotated tools are gated so a new tool cannot slip through unguarded.
    read_only = _annotated_tool("siem_search", {"readOnlyHint": True})
    low_risk_write = _annotated_tool(
        "write_sigma_rule", {"readOnlyHint": False, "destructiveHint": False}
    )
    destructive = _annotated_tool(
        "siem_deploy_rule", {"readOnlyHint": False, "destructiveHint": True}
    )
    unannotated = _annotated_tool("future_tool", None)

    guarded = derive_guarded_tool_names([read_only, low_risk_write, destructive, unannotated])

    assert guarded == {"siem_deploy_rule", "future_tool"}


def test_routing_digest_compacts_transcript() -> None:
    # The router prompt must stay small: keep the user goal, summarize assistant
    # text, truncate bulky tool output, and drop empty tool-call messages so a
    # small local model's context window cannot overflow and mis-route.
    messages = [
        HumanMessage(content="deploy rule r1"),
        AIMessage(content="", tool_calls=[{"name": "siem_search", "args": {}, "id": "1"}]),
        ToolMessage(content="x" * 5000, name="siem_search", tool_call_id="1"),
        AIMessage(content="Deployed r1 successfully.", name="deployment_operator"),
    ]

    digest = _routing_digest(messages)

    assert "Current request:\ndeploy rule r1" in digest
    assert "deployment_operator: Deployed r1 successfully." in digest
    assert "(ran siem_search)" in digest
    assert "x" * 5000 not in digest  # bulky tool payload is truncated
    assert len(digest) < 1200  # bounded regardless of transcript size


def test_routing_digest_isolates_current_request_from_prior_turns() -> None:
    # Regression: across turns the digest must route on the LATEST human request,
    # not a concatenation of every past request, and finished work from earlier
    # turns must not count as progress on the new request. Otherwise a history
    # dominated by one specialist (e.g. rule authoring) drags every later request
    # — such as a coverage question — back to that same specialist.
    messages = [
        HumanMessage(content="write a sigma rule for sudo abuse"),
        AIMessage(content="Rule written.", name="rule_author"),
        HumanMessage(content="what is my current coverage?"),
    ]

    digest = _routing_digest(messages)

    # The newest request is highlighted as the thing to route on.
    assert "Current request:\nwhat is my current coverage?" in digest
    # The prior request is demoted to context, after the current one.
    assert "write a sigma rule for sudo abuse" in digest
    assert digest.index("what is my current coverage?") < digest.index(
        "write a sigma rule for sudo abuse"
    )
    # Finished rule-author work from the previous turn is not replayed as current
    # progress, so it cannot bias routing back to rule_author.
    assert "rule_author: Rule written." not in digest


def test_parse_mention_extracts_known_specialist() -> None:
    # A leading "@specialist" mention is split off (case-insensitively) and the
    # rest is the request; unknown names and bare text are left untouched so a
    # literal leading "@" is never silently dropped.
    valid = {"hunt_analyst", "rule_author"}
    assert _parse_mention("@hunt_analyst search the siem", valid) == (
        "hunt_analyst",
        "search the siem",
    )
    assert _parse_mention("@Rule_Author write a rule", valid) == ("rule_author", "write a rule")
    assert _parse_mention("@hunt_analyst", valid) == ("hunt_analyst", "")
    assert _parse_mention("@unknown do x", valid) == (None, "@unknown do x")
    assert _parse_mention("just a question", valid) == (None, "just a question")
    assert _parse_mention("@", valid) == (None, "@")


async def test_route_override_forces_specialist(tmp_path: Path) -> None:
    # An @specialist override must pin the first hop to that specialist without
    # consulting the router. With a single specialist and no override, the
    # supervisor's first model reply ("Investigated...") parses to FINISH and the
    # specialist never runs; the override is what makes it run, so its answer
    # appearing proves the override took effect.
    spec = SpecialistSpec(
        name="rule_author",
        title="Detection Rule Author",
        description="Authors detection rules.",
        system_prompt="Author detection rules.",
        tool_names=frozenset({"siem_search"}),
    )
    script: list[BaseMessage] = [
        AIMessage(content="Investigated; nothing found."),  # specialist's answer
        AIMessage(content="FINISH"),  # supervisor finishes after hand-back
    ]
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = build_supervisor_graph(
        ScriptedModel(responses=script),
        [_make_search_tool()],
        audit=audit,
        dangerous=set(),
        specialists=(spec,),
        checkpointer=InMemorySaver(),
    )
    session = AgentSession(app=graph, audit=audit, settings=Settings(_env_file=None))  # type: ignore[call-arg]
    events: list[ProgressEvent] = []

    async def _no_approval(_payload: dict[str, Any]) -> ApprovalDecision:
        raise AssertionError("no approval expected for a read-only tool")

    result = await session.run_turn(
        "t-override",
        "find evil",
        on_interrupt=_no_approval,
        on_event=events.append,
        route_override="rule_author",
    )

    assert any(e.kind == "route" and e.label == "rule_author" for e in events)
    texts = [message_text(m) for m in result["messages"]]
    assert any("Investigated; nothing found." in text for text in texts)
    assert result["next"] == FINISH


async def test_run_turn_streams_progress_events(tmp_path: Path) -> None:
    # The turn must surface its stages (routing + the specialist's tool use) so
    # the CLI can show what is happening instead of raw HTTP traffic.
    spec = SpecialistSpec(
        name="hunt_analyst",
        title="Threat Hunter",
        description="Hunts across the SIEM.",
        system_prompt="Hunt for threats.",
        tool_names=frozenset({"siem_search"}),
    )
    script: list[BaseMessage] = [
        AIMessage(content="hunt_analyst"),
        AIMessage(
            content="",
            tool_calls=[{"name": "siem_search", "args": {"query": "evil"}, "id": "s1"}],
        ),
        AIMessage(content="Found nothing suspicious."),
        AIMessage(content="FINISH"),
    ]
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = build_supervisor_graph(
        ScriptedModel(responses=script),
        [_make_search_tool()],
        audit=audit,
        dangerous=set(),
        specialists=(spec,),
        checkpointer=InMemorySaver(),
    )
    session = AgentSession(app=graph, audit=audit, settings=Settings(_env_file=None))  # type: ignore[call-arg]
    events: list[ProgressEvent] = []

    async def _no_approval(_payload: dict[str, Any]) -> ApprovalDecision:
        raise AssertionError("no approval expected for a read-only tool")

    result = await session.run_turn(
        "t-progress", "hunt for evil", on_interrupt=_no_approval, on_event=events.append
    )

    assert any(e.kind == "route" and e.label == "hunt_analyst" for e in events)
    assert any(e.kind == "specialist" and "siem_search" in e.tools for e in events)
    texts = [message_text(m) for m in result["messages"]]
    assert any("Found nothing suspicious." in text for text in texts)


async def test_run_turn_streaming_preserves_approval_gate(tmp_path: Path) -> None:
    # Streaming the turn must not break the human-approval interrupt: a guarded
    # tool still pauses for a decision before it executes.
    executed: list[str] = []
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _build_deploy_graph(audit, _make_deploy_tool(executed))
    session = AgentSession(app=graph, audit=audit, settings=Settings(_env_file=None))  # type: ignore[call-arg]
    requested: list[dict[str, Any]] = []

    async def _approve(payload: dict[str, Any]) -> ApprovalDecision:
        requested.append(payload)
        return ApprovalDecision(action="approve")

    result = await session.run_turn(
        "t-approve-stream", "deploy rule r1", on_interrupt=_approve, on_event=lambda _e: None
    )

    assert requested, "guarded tool should have paused for approval"
    assert executed == ["r1"]
    texts = [message_text(m) for m in result["messages"]]
    assert any("DEPLOYED r1" in text for text in texts)


async def test_supervisor_breaks_self_delegation_loop(tmp_path: Path) -> None:
    # Once a specialist emits its final answer, the supervisor must not route
    # straight back to that same specialist (which only repeats finished work and
    # can hang a slow local model); it should finish the turn instead. Without the
    # guard this scripted graph would loop until the recursion limit.
    spec = SpecialistSpec(
        name="rule_author",
        title="Detection Rule Author",
        description="Authors detection rules.",
        system_prompt="Author detection rules.",
        tool_names=frozenset({"siem_search"}),
    )
    script: list[BaseMessage] = [
        AIMessage(content="rule_author"),  # supervisor: delegate
        AIMessage(content="Rule written.", name="rule_author"),  # specialist: final answer
        AIMessage(content="rule_author"),  # supervisor: would self-loop -> forced FINISH
    ]
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = build_supervisor_graph(
        ScriptedModel(responses=script),
        [_make_search_tool()],
        audit=audit,
        dangerous=set(),
        specialists=(spec,),
        checkpointer=InMemorySaver(),
    )
    config = {"configurable": {"thread_id": "t-self-loop"}}

    result = await graph.ainvoke({"messages": [HumanMessage(content="write a rule")]}, config)

    assert result["next"] == FINISH
    texts = [message_text(m) for m in result["messages"]]
    # The specialist ran exactly once; its single answer is not repeated.
    assert sum("Rule written." in text for text in texts) == 1


class _TimeoutModel(BaseChatModel):
    """A chat model whose generation raises an empty async-style read timeout."""

    @property
    def _llm_type(self) -> str:
        return "timeout"

    def bind_tools(self, tools: Any, **kwargs: Any) -> _TimeoutModel:
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        # The real async Ollama timeout is an httpx.ReadTimeout with an empty message.
        raise httpx.ReadTimeout("")


async def test_run_turn_translates_model_timeout(tmp_path: Path) -> None:
    # A model timeout (empty-message async httpx.ReadTimeout) must surface as a
    # clear, typed ModelTimeoutError instead of a blank "Turn failed:" line.
    spec = SpecialistSpec(
        name="hunt_analyst",
        title="Threat Hunter",
        description="Hunts across the SIEM.",
        system_prompt="Hunt for threats.",
        tool_names=frozenset({"siem_search"}),
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = build_supervisor_graph(
        _TimeoutModel(),
        [_make_search_tool()],
        audit=audit,
        dangerous=set(),
        specialists=(spec,),
        checkpointer=InMemorySaver(),
    )
    session = AgentSession(app=graph, audit=audit, settings=Settings(_env_file=None))  # type: ignore[call-arg]

    async def _no_approval(_payload: dict[str, Any]) -> ApprovalDecision:
        raise AssertionError("no approval expected when the model times out")

    with pytest.raises(ModelTimeoutError):
        await session.run_turn(
            "t-timeout", "hunt for evil", on_interrupt=_no_approval, on_event=lambda _e: None
        )


async def test_tool_error_is_returned_to_model_not_crashing_turn(tmp_path: Path) -> None:
    # A failing tool call must come back to the specialist as an error message so
    # it can self-correct, instead of aborting the entire turn (regression guard:
    # create_agent's default tool node re-raises tool exceptions).
    async def _fail(cve_id: str = "") -> str:
        raise ToolException("invalid CVE id: '' (expected CVE-YYYY-NNNN)")

    failing = StructuredTool.from_function(
        coroutine=_fail, name="lookup_cve", description="Look up a CVE."
    )
    spec = SpecialistSpec(
        name="rule_author",
        title="Detection Rule Author",
        description="Authors detection rules.",
        system_prompt="Author detection rules.",
        tool_names=frozenset({"lookup_cve"}),
    )
    script: list[BaseMessage] = [
        AIMessage(content="rule_author"),
        AIMessage(
            content="",
            tool_calls=[
                {"name": "lookup_cve", "args": {"cve_id": ""}, "id": "c1", "type": "tool_call"}
            ],
        ),
        AIMessage(content="CVE lookup failed; authoring without CVE context."),
        AIMessage(content="FINISH"),
    ]
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = build_supervisor_graph(
        ScriptedModel(responses=script),
        [failing],
        audit=audit,
        dangerous=set(),
        specialists=(spec,),
        checkpointer=InMemorySaver(),
    )
    config = {"configurable": {"thread_id": "t-tool-error"}}

    result = await graph.ainvoke(
        {"messages": [HumanMessage(content="look up a CVE for whoami")]}, config
    )

    assert "__interrupt__" not in result
    tool_messages = [m for m in result["messages"] if m.type == "tool"]
    assert any("invalid CVE id" in message_text(m) for m in tool_messages)
    assert any(getattr(m, "status", None) == "error" for m in tool_messages)
    texts = [message_text(m) for m in result["messages"]]
    assert any("authoring without CVE context" in text for text in texts)



def test_full_supervisor_graph_compiles(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    model = ScriptedModel(responses=[AIMessage(content="FINISH")])
    graph = build_supervisor_graph(
        model,
        [_make_deploy_tool([])],
        audit=audit,
        dangerous={"siem_deploy_rule"},
        checkpointer=InMemorySaver(),
    )

    nodes = set(graph.get_graph().nodes)
    assert "supervisor" in nodes
    for spec in SPECIALISTS:
        assert spec.name in nodes


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_audit_log_roundtrip(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "nested" / "audit.jsonl")
    assert audit.entries() == []

    first = audit.record("approval_decision", tool="siem_deploy_rule", action="approve")
    audit.record("tool_executed", tool="siem_deploy_rule", arguments={"rule_id": "r1"})

    entries = audit.entries()
    assert [entry["event"] for entry in entries] == ["approval_decision", "tool_executed"]
    assert "timestamp" in first
    assert entries[0]["tool"] == "siem_deploy_rule"
    assert entries[1]["arguments"] == {"rule_id": "r1"}


# ---------------------------------------------------------------------------
# Thread history helpers
# ---------------------------------------------------------------------------


def test_list_threads_missing_empty_and_populated(tmp_path: Path) -> None:
    assert list_threads(tmp_path / "missing.sqlite") == []

    empty = tmp_path / "empty.sqlite"
    sqlite3.connect(empty).close()
    assert list_threads(empty) == []

    populated = tmp_path / "history.sqlite"
    connection = sqlite3.connect(populated)
    connection.execute("CREATE TABLE checkpoints (thread_id TEXT, checkpoint_id TEXT)")
    connection.executemany(
        "INSERT INTO checkpoints VALUES (?, ?)",
        [("beta", "1"), ("alpha", "1"), ("alpha", "2")],
    )
    connection.commit()
    connection.close()
    assert list_threads(populated) == ["alpha", "beta"]


def test_new_thread_id_format() -> None:
    assert re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{6}", new_thread_id())


# ---------------------------------------------------------------------------
# Supervisor parsing helpers and approval model
# ---------------------------------------------------------------------------


def test_parse_choice_exact_substring_and_default() -> None:
    options = {"hunt_analyst", "deployment_operator", FINISH}
    assert _parse_choice("hunt_analyst", options) == "hunt_analyst"
    assert _parse_choice("I think deployment_operator should act", options) == "deployment_operator"
    assert _parse_choice("no clear answer here", options) == FINISH


def test_parse_choice_requires_whole_word_match() -> None:
    options = {"hunt_analyst", "deployment_operator", FINISH}
    # A larger surrounding word must not trigger a partial-substring route.
    assert _parse_choice("the deployment_operators stood down", options) == FINISH


def test_parse_choice_prefers_earliest_named_specialist() -> None:
    options = {"hunt_analyst", "deployment_operator", FINISH}
    # When several specialists are named, the first one mentioned wins.
    assert _parse_choice("deployment_operator then hunt_analyst", options) == "deployment_operator"
    assert _parse_choice("hunt_analyst before deployment_operator", options) == "hunt_analyst"


def test_message_text_handles_str_and_blocks() -> None:
    assert message_text(AIMessage(content="hello world")) == "hello world"
    blocks = AIMessage(
        content=[
            {"type": "text", "text": "foo "},
            {"type": "text", "text": "bar"},
            {"type": "image", "url": "ignored"},
        ]
    )
    assert message_text(blocks) == "foo bar"


def test_approval_decision_defaults_to_reject() -> None:
    decision = ApprovalDecision.model_validate({})
    assert decision.action == "reject"
    assert decision.edited_arguments is None
    assert decision.feedback == ""
