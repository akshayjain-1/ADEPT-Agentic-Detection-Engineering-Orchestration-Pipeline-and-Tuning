"""Runtime session that wires the agent graph to MCP tools and persistence."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx
from langchain_core.messages import HumanMessage
from langgraph.types import Command

from adept.agent.approval import derive_guarded_tool_names
from adept.agent.audit import AuditLog
from adept.agent.llm import build_chat_model
from adept.agent.mcp_client import load_tools
from adept.agent.supervisor import build_supervisor_graph
from adept.shared.errors import ModelTimeoutError

if TYPE_CHECKING:
    from adept.agent.approval import ApprovalDecision
    from adept.config.settings import Settings

InterruptHandler = Callable[[dict[str, Any]], Awaitable["ApprovalDecision"]]

#: Internal node that picks the next specialist; not a user-facing stage.
_SUPERVISOR_NODE = "supervisor"

#: Internal node that lints a specialist's output and may loop it back.
_EVALUATOR_NODE = "evaluator"


@dataclass(slots=True)
class ProgressEvent:
    """A human-meaningful step within a turn, surfaced to the UI as it happens.

    ``kind`` is ``"route"`` when the supervisor delegates to a specialist
    (``label`` is that specialist, or ``"FINISH"`` when the turn is wrapping up)
    or ``"specialist"`` when a specialist finishes a step (``tools`` lists the
    tools it called, in order). ``kind`` is ``"evaluate"`` when the critic node
    reviews a specialist's output (``label`` is ``"passed"``,
    ``"regenerate:<specialist>"``, or ``"escalated"``).
    """

    kind: str
    label: str
    tools: tuple[str, ...] = field(default=())


ProgressHandler = Callable[[ProgressEvent], None]


def _progress_from_update(update: dict[str, Any]) -> Iterator[ProgressEvent]:
    """Translate one ``stream_mode='updates'`` chunk into progress events."""
    for node, value in update.items():
        if node == _SUPERVISOR_NODE:
            nxt = value.get("next") if isinstance(value, dict) else None
            if nxt:
                yield ProgressEvent(kind="route", label=str(nxt))
        elif node == _EVALUATOR_NODE and isinstance(value, dict):
            route = value.get("eval_route")
            messages = value.get("messages") or []
            escalated = any(getattr(m, "name", None) == _EVALUATOR_NODE for m in messages)
            if route and route != _SUPERVISOR_NODE:
                label = f"regenerate:{route}"
            elif escalated:
                label = "escalated"
            else:
                label = "passed"
            yield ProgressEvent(kind="evaluate", label=label)
        elif isinstance(value, dict):
            tools: list[str] = []
            for message in value.get("messages") or []:
                for call in getattr(message, "tool_calls", None) or []:
                    name = call.get("name") if isinstance(call, dict) else None
                    if name:
                        tools.append(str(name))
            yield ProgressEvent(kind="specialist", label=str(node), tools=tuple(tools))


@dataclass(slots=True)
class AgentSession:
    """A live agent graph bound to a checkpointer and audit log."""

    app: Any
    audit: AuditLog
    settings: Settings

    async def run_turn(
        self,
        thread_id: str,
        user_input: str,
        *,
        on_interrupt: InterruptHandler,
        on_event: ProgressHandler | None = None,
        route_override: str | None = None,
    ) -> dict[str, Any]:
        """Run one user turn, pausing for approval whenever a guarded tool fires.

        The turn is streamed so the caller can surface progress: ``on_event`` (if
        given) is called with a :class:`ProgressEvent` for each routing decision
        and specialist step, replacing opaque waiting with visible stages.

        ``on_interrupt`` is awaited with the approval payload each time the graph
        pauses and must return an :class:`ApprovalDecision`. The final graph
        state is returned once no interrupts remain.

        ``route_override`` (set from an ``@specialist`` mention) pins the first
        routing hop to that specialist; the supervisor consumes it and then
        routes normally for the rest of the turn.
        """
        config: dict[str, Any] = {
            "configurable": {"thread_id": thread_id},
            "recursion_limit": self.settings.agent.recursion_limit,
        }
        payload: Any = {"messages": [HumanMessage(content=user_input)]}
        if route_override:
            payload["route_override"] = route_override
        try:
            while True:
                interrupts: list[Any] = []
                async for update in self.app.astream(payload, config, stream_mode="updates"):
                    pending = update.get("__interrupt__")
                    if pending is not None:
                        interrupts.extend(pending)
                    elif on_event is not None:
                        for event in _progress_from_update(update):
                            on_event(event)
                if not interrupts:
                    break
                # A single turn may raise several interrupts (e.g. a specialist emits
                # multiple guarded tool calls). Collect a decision for each and resume
                # with an id-keyed map so every pending approval is answered.
                resume_map: dict[str, Any] = {}
                for pending in interrupts:
                    decision = await on_interrupt(pending.value)
                    resume_map[pending.id] = decision.model_dump()
                payload = Command(resume=resume_map)
        except (httpx.TimeoutException, TimeoutError) as exc:
            # The async Ollama timeout surfaces as an ``httpx.ReadTimeout`` whose
            # message is empty, which would otherwise print as a blank "Turn
            # failed:" line. Translate it into an actionable, typed error.
            timeout = self.settings.ollama.request_timeout
            raise ModelTimeoutError(
                f"The model did not respond within {timeout}s. The local model may be "
                "too slow for this request — increase `ollama.request_timeout`, switch to "
                "a smaller/faster model, or run Ollama with GPU acceleration."
            ) from exc
        snapshot = await self.app.aget_state(config)
        return dict(snapshot.values)


@contextlib.asynccontextmanager
async def open_agent_session(settings: Settings) -> AsyncIterator[AgentSession]:
    """Open an agent session: connect to the MCP server and the checkpoint DB."""
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    model = build_chat_model(settings)
    tools = await load_tools(settings)
    audit = AuditLog(settings.agent.audit_log)
    # Derive the approval gate from the server's tool annotations (fail-safe
    # default-deny) and union the operator's explicit overrides on top.
    dangerous = derive_guarded_tool_names(tools) | set(settings.agent.dangerous_tools)
    db_path = settings.agent.checkpoint_db
    db_path.parent.mkdir(parents=True, exist_ok=True)
    async with AsyncSqliteSaver.from_conn_string(str(db_path)) as saver:
        await saver.setup()
        graph = build_supervisor_graph(
            model, tools, audit=audit, dangerous=dangerous, checkpointer=saver, settings=settings
        )
        yield AgentSession(app=graph, audit=audit, settings=settings)
