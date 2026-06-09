"""Build the ADEPT hybrid-supervisor LangGraph graph.

A lightweight supervisor node routes the conversation to one specialist at a
time. Each specialist is a tool-calling agent (``langchain.agents.create_agent``)
restricted to the MCP tools for its role. Specialists run sequentially, which
suits CPU-bound local inference, and state-changing tools are wrapped by the
human-in-the-loop approval gate.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Hashable, Sequence
from typing import TYPE_CHECKING, Any, cast

from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
from langchain_core.messages import AnyMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.errors import GraphBubbleUp
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from adept.agent.approval import guard_tools
from adept.agent.specialists import SPECIALISTS, SpecialistSpec
from adept.agent.state import SupervisorState

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from langchain_core.tools import BaseTool

    from adept.agent.audit import AuditLog

FINISH = "FINISH"

SupervisorNode = Callable[[SupervisorState], Awaitable[dict[str, Any]]]


def message_text(message: Any) -> str:
    """Extract plain text from a message whose content may be blocks."""
    content = message.content
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict):
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def _supervisor_prompt(specialists: Sequence[SpecialistSpec]) -> str:
    lines = [
        "You are the supervisor of a detection-engineering team. Route the user's "
        "CURRENT request to the one specialist best suited to act on it next. Use the "
        "progress so far only to avoid repeating finished work and to judge when the "
        "current request is complete; do not let earlier, already-handled requests "
        "pull the choice toward the specialist that handled them.",
        "",
        "Specialists:",
    ]
    lines += [f"- {spec.name}: {spec.description}" for spec in specialists]
    lines += [
        f"- {FINISH}: the current request is fully satisfied; stop.",
        "",
        f"Reply with ONLY one name from the list above (or {FINISH}). Output nothing else.",
    ]
    return "\n".join(lines)


def _parse_choice(text: str, options: set[str]) -> str:
    """Map a supervisor reply to one of ``options`` (defaulting to FINISH).

    An exact (case-insensitive) reply wins outright. Otherwise the reply is
    scanned for a whole-word mention of an option and the earliest match is
    chosen, so an incidental substring cannot mis-route and the first specialist
    the supervisor names takes precedence. Anything else falls back to FINISH.
    """
    lowered = text.strip().lower()
    for option in options:
        if lowered == option.lower():
            return option
    best_option = FINISH
    best_pos = len(lowered) + 1
    for option in options:
        match = re.search(rf"\b{re.escape(option.lower())}\b", lowered)
        if match is not None and match.start() < best_pos:
            best_pos = match.start()
            best_option = option
    return best_option


_ROUTING_HISTORY_LIMIT = 6
_ROUTING_SNIPPET_CHARS = 400
_ROUTING_TOOL_SNIPPET_CHARS = 160


def _snippet(text: str, limit: int) -> str:
    """Collapse whitespace and hard-truncate ``text`` to ``limit`` characters."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit].rstrip() + "..."


def _routing_digest(messages: Sequence[AnyMessage]) -> str:
    """Compact the transcript into a small, bounded, turn-isolated routing prompt.

    Feeding the full transcript — including tool-call payloads such as SIEM hits
    and rule bodies — to a small local router model can overflow its context
    window and cause mis-routing. The router only needs the *current* request and
    a short trace of what has been done on it, so the latest human turn is
    highlighted as the request to route on, earlier (already-handled) turns are
    demoted to brief context, and assistant/tool output is truncated.

    Crucially, only activity *after* the latest human message counts as progress
    on the current request. Without this isolation a multi-turn conversation
    accumulates every past request and every specialist's past work into the
    prompt, biasing the router toward whichever specialist dominated the history
    regardless of what the user just asked.
    """
    last_human = -1
    for index, message in enumerate(messages):
        if getattr(message, "type", "") == "human":
            last_human = index

    current_request = "(none provided)"
    earlier_requests: list[str] = []
    if last_human >= 0:
        current_request = (
            _snippet(message_text(messages[last_human]), _ROUTING_SNIPPET_CHARS)
            or "(none provided)"
        )
        for message in messages[:last_human]:
            if getattr(message, "type", "") == "human":
                text = _snippet(message_text(message), _ROUTING_SNIPPET_CHARS)
                if text:
                    earlier_requests.append(text)

    progress: list[str] = []
    for message in messages[last_human + 1 :]:
        kind = getattr(message, "type", "")
        if kind == "ai":
            text = _snippet(message_text(message), _ROUTING_SNIPPET_CHARS)
            if text:
                name = getattr(message, "name", None) or "assistant"
                progress.append(f"{name}: {text}")
        elif kind == "tool":
            name = getattr(message, "name", None) or "tool"
            payload = _snippet(message_text(message), _ROUTING_TOOL_SNIPPET_CHARS)
            progress.append(f"(ran {name}) {payload}".rstrip())

    sections = [f"Current request:\n{current_request}"]
    if earlier_requests:
        earlier_block = "\n".join(
            f"- {item}" for item in earlier_requests[-_ROUTING_HISTORY_LIMIT:]
        )
        sections.append(
            "Earlier requests this conversation (already handled \u2014 context only):\n"
            f"{earlier_block}"
        )
    if progress:
        progress_block = "\n".join(f"- {item}" for item in progress[-_ROUTING_HISTORY_LIMIT:])
    else:
        progress_block = "- (nothing yet \u2014 route the current request to the right specialist)"
    sections.append(f"Progress on the current request (most recent last):\n{progress_block}")
    return "\n\n".join(sections)


def _specialist_just_finished(messages: Sequence[AnyMessage], name: str) -> bool:
    """Return True if the latest message is ``name``'s completed answer.

    A specialist agent loops internally on its own tools until it emits a final
    ``AIMessage`` with no tool calls. Routing straight back to that same
    specialist — with no new user input since — only repeats finished work and,
    on a slow local model, risks a needless timeout, so the supervisor treats it
    as turn completion instead.
    """
    if not messages:
        return False
    last = messages[-1]
    return (
        getattr(last, "type", "") == "ai"
        and getattr(last, "name", None) == name
        and not (getattr(last, "tool_calls", None) or [])
        and bool(message_text(last).strip())
    )


def make_supervisor_node(
    model: BaseChatModel, specialists: Sequence[SpecialistSpec]
) -> SupervisorNode:
    """Create the async supervisor node that selects the next specialist."""
    options = {spec.name for spec in specialists} | {FINISH}
    prompt = _supervisor_prompt(specialists)

    async def supervisor(state: SupervisorState) -> dict[str, Any]:
        messages = state["messages"]
        override = state.get("route_override")
        if override and override in options and override != FINISH:
            # An explicit user "@specialist" override pins this hop: route there
            # without consulting the model, then clear it so the specialist's
            # hand-back and any later hops route normally.
            return {"next": override, "route_override": ""}
        conversation = [
            SystemMessage(content=prompt),
            HumanMessage(content=_routing_digest(messages)),
        ]
        reply = await model.ainvoke(conversation)
        choice = _parse_choice(message_text(reply), options)
        # Guard against a specialist being re-delegated to itself the instant it
        # finishes: that only repeats completed work and can hang on a slow model.
        if choice != FINISH and _specialist_just_finished(messages, choice):
            choice = FINISH
        return {"next": choice}

    return supervisor


class _ToolErrorRecoveryMiddleware(AgentMiddleware):
    """Return tool failures to the model instead of crashing the whole turn.

    ``create_agent``'s default tool node re-raises any tool exception that is not
    an argument-validation error, so a single failing MCP tool call (an invalid
    CVE id, malformed rule YAML, a momentarily unreachable backend) aborts the
    entire turn. Converting the failure into an ``error`` :class:`ToolMessage`
    lets the specialist see what went wrong and self-correct on its next step.

    The human-approval gate raises a LangGraph ``interrupt`` (a ``GraphBubbleUp``)
    from inside guarded tools; that must propagate untouched, so it is re-raised
    before any error is captured.
    """

    @staticmethod
    def _error_message(request: ToolCallRequest, exc: Exception) -> ToolMessage:
        return ToolMessage(
            content=f"Tool {request.tool_call['name']!r} failed: {exc}",
            tool_call_id=request.tool_call["id"],
            status="error",
        )

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        try:
            return handler(request)
        except GraphBubbleUp:
            raise
        except Exception as exc:
            return self._error_message(request, exc)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        try:
            return await handler(request)
        except GraphBubbleUp:
            raise
        except Exception as exc:
            return self._error_message(request, exc)


_TOOL_ERROR_RECOVERY = _ToolErrorRecoveryMiddleware()


def build_specialist_agents(
    model: BaseChatModel,
    tools: list[BaseTool],
    specialists: Sequence[SpecialistSpec],
    *,
    audit: AuditLog,
    dangerous: set[str],
) -> dict[str, Any]:
    """Build one tool-calling agent per specialist with role-scoped tools."""
    guarded = guard_tools(tools, dangerous, audit=audit)
    by_name = {tool.name: tool for tool in guarded}
    agents: dict[str, Any] = {}
    for spec in specialists:
        subset = [by_name[name] for name in spec.tool_names if name in by_name]
        agents[spec.name] = create_agent(
            model,
            tools=subset,
            system_prompt=spec.system_prompt,
            name=spec.name,
            middleware=[_TOOL_ERROR_RECOVERY],
        )
    return agents


def build_supervisor_graph(
    model: BaseChatModel,
    tools: list[BaseTool],
    *,
    audit: AuditLog,
    dangerous: set[str],
    specialists: Sequence[SpecialistSpec] = SPECIALISTS,
    checkpointer: Any = None,
) -> Any:
    """Assemble and compile the supervisor + specialist graph."""
    agents = build_specialist_agents(model, tools, specialists, audit=audit, dangerous=dangerous)
    builder = StateGraph(SupervisorState)
    # ``add_node``'s overloads can't infer NodeInputT for an async TypedDict-state
    # node, so cast the node; the supervisor signature is enforced by SupervisorNode.
    builder.add_node("supervisor", cast(Any, make_supervisor_node(model, specialists)))
    routes: dict[Hashable, str] = {}
    for spec in specialists:
        builder.add_node(spec.name, agents[spec.name])
        builder.add_edge(spec.name, "supervisor")
        routes[spec.name] = spec.name
    routes[FINISH] = END
    builder.add_edge(START, "supervisor")
    builder.add_conditional_edges("supervisor", lambda state: state["next"], routes)
    return builder.compile(checkpointer=checkpointer)
