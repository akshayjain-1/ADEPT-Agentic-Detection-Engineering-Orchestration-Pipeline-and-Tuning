"""Human-in-the-loop approval gate for state-changing tools.

State-changing MCP tools (deploying, disabling or deleting detections, and
attack-simulation) are wrapped so that invoking them pauses the graph with a
LangGraph ``interrupt``. The CLI renders the request, collects a decision, and
resumes the graph with an :class:`ApprovalDecision`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from langchain_core.tools import BaseTool, StructuredTool
from langgraph.types import interrupt
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from adept.agent.audit import AuditLog

ApprovalAction = Literal["approve", "edit", "reject", "request_changes"]


class ApprovalRequest(BaseModel):
    """Payload surfaced to the human when a guarded tool is invoked."""

    tool: str
    summary: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    """The human's response to an :class:`ApprovalRequest`.

    ``edited_arguments`` is only honoured for the ``"edit"`` action; ``feedback``
    is surfaced back to the agent for the ``"request_changes"`` action.
    """

    action: ApprovalAction = "reject"
    edited_arguments: dict[str, Any] | None = None
    feedback: str = ""


def _summarize(tool: str, arguments: dict[str, Any]) -> str:
    rendered = ", ".join(f"{key}={value!r}" for key, value in arguments.items())
    return f"{tool}({rendered})"


def guard_tool(tool: BaseTool, *, audit: AuditLog) -> BaseTool:
    """Wrap ``tool`` so it requires human approval before it executes.

    The wrapper keeps the original name, description and argument schema so the
    model sees an identical interface. On invocation it raises an ``interrupt``
    carrying an :class:`ApprovalRequest`; the resume value is parsed as an
    :class:`ApprovalDecision` which decides whether (and with which arguments)
    the underlying tool runs. Every decision is appended to the audit log.
    """
    name = tool.name

    async def _guarded(**kwargs: Any) -> Any:
        request = ApprovalRequest(tool=name, summary=_summarize(name, kwargs), arguments=kwargs)
        raw = interrupt(request.model_dump())
        decision = (
            raw if isinstance(raw, ApprovalDecision) else ApprovalDecision.model_validate(raw)
        )
        audit.record(
            "approval_decision",
            tool=name,
            action=decision.action,
            arguments=kwargs,
            feedback=decision.feedback,
        )
        if decision.action in ("approve", "edit"):
            arguments = (
                decision.edited_arguments
                if decision.action == "edit" and decision.edited_arguments is not None
                else kwargs
            )
            audit.record("tool_executed", tool=name, arguments=arguments)
            return await tool.ainvoke(arguments)
        if decision.action == "request_changes":
            return f"Human requested changes (tool not executed): {decision.feedback}".strip()
        return f"Human rejected execution of {name!r}; the action was not performed."

    schema = tool.args_schema
    if schema is not None:
        return StructuredTool.from_function(
            coroutine=_guarded,
            name=name,
            description=tool.description,
            args_schema=schema,
            infer_schema=False,
        )
    return StructuredTool.from_function(
        coroutine=_guarded,
        name=name,
        description=tool.description,
    )


def guard_tools(tools: list[BaseTool], dangerous: set[str], *, audit: AuditLog) -> list[BaseTool]:
    """Return ``tools`` with any whose name is in ``dangerous`` wrapped by the gate."""
    return [guard_tool(tool, audit=audit) if tool.name in dangerous else tool for tool in tools]


def _tool_requires_approval(tool: BaseTool) -> bool:
    """Decide whether ``tool`` must pass the human-approval gate.

    Fail-safe default-deny driven by the server's MCP tool annotations:

    * explicitly read-only (``readOnlyHint`` true) -> never gated;
    * an explicitly non-destructive write (``destructiveHint`` false) -> not gated;
    * everything else — destructive *or unannotated* -> gated.

    Because an unannotated (e.g. newly added) tool falls through to the last
    case, the gate cannot silently miss a state-changing tool.
    """
    meta = tool.metadata or {}
    if meta.get("readOnlyHint") is True:
        return False
    if meta.get("destructiveHint") is False:
        return False
    return True


def derive_guarded_tool_names(tools: list[BaseTool]) -> set[str]:
    """Names of tools that require approval, derived from their MCP annotations.

    This makes the server the single source of truth for what is state-changing
    instead of a hand-maintained client-side denylist that can drift open.
    """
    return {tool.name for tool in tools if _tool_requires_approval(tool)}
