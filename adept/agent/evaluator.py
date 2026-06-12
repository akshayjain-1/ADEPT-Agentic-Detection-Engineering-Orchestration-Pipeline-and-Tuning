"""Evaluator (critic) node for the ADEPT supervisor graph.

After a specialist finishes a hop, this node deterministically lints what the
specialist actually produced — written Sigma rules, git operations, converted
SIEM queries, exported Navigator layers, and any query/rule fenced in the final
answer — using the offline :mod:`adept.guardrails` linters. Anything with a
blocking (``error``) finding is sent back to the *same* specialist with a
concrete critique so it can regenerate, up to ``eval_max_retries`` times; once
the retry budget is spent the work is surfaced to the human with the unresolved
issues attached. Clean output (optionally double-checked by a lenient LLM judge)
proceeds to the supervisor.

The node only re-lints tool calls that actually executed: a call whose paired
``ToolMessage`` came back with ``status="error"`` (for example, refused by the
submit-time lint middleware or a backend failure) is skipped, so the evaluator
never regenerates against an input the agent already self-corrected away from.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage

from adept.agent.state import EVALUATOR_FEEDBACK_NAME, SupervisorState
from adept.agent.supervisor import message_text
from adept.guardrails import (
    lint_lucene,
    lint_navigator_layer,
    lint_query,
    lint_sigma,
    lint_spl,
    lint_tool_input,
)

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

    from adept.agent.audit import AuditLog
    from adept.agent.specialists import SpecialistSpec
    from adept.config.settings import Settings
    from adept.guardrails.models import LintFinding, LintReport

#: Routing target meaning "the output is acceptable, hand back to the router".
SUPERVISOR_TARGET = "supervisor"

#: Name tag on the evaluator's own escalation note (an ``AIMessage``).
EVALUATOR_NAME = "evaluator"

EvaluatorNode = Callable[[SupervisorState], Awaitable[dict[str, Any]]]

#: Fenced code block: ```lang\n...body...```. ``lang`` may be empty.
_FENCE_RE = re.compile(r"```([A-Za-z0-9_+-]*)\n(.*?)```", re.DOTALL)

#: Fence languages that carry each artifact type.
_SPL_LANGS = frozenset({"spl", "splunk"})
_SIGMA_LANGS = frozenset({"sigma"})
_LUCENE_LANGS = frozenset({"lucene", "elasticsearch"})

#: Tool results whose payload carries a lintable artifact.
_RESULT_TOOLS = frozenset({"convert_sigma_rule", "export_navigator_layer"})

#: Judge prompt: a deliberately lenient second-opinion to catch semantic issues
#: the deterministic linters cannot see, without nagging on stylistic nits.
_JUDGE_SYSTEM = (
    "You review a detection-engineering specialist's work before it reaches a "
    "teammate. Decide only whether the work needs another attempt. Reply with "
    "exactly 'PASS' if it is correct and reasonably complete, or "
    "'REVISE: <one concise reason>' if it has a substantive correctness or "
    "safety problem. Prefer PASS; do not request revisions for style alone."
)


def _hop_messages(messages: Sequence[AnyMessage]) -> list[AnyMessage]:
    """Return the messages produced since the most recent human message.

    Both genuine user turns and the evaluator's own regeneration feedback (a
    ``HumanMessage``) reset this window, so each call inspects only the latest
    specialist attempt rather than the whole conversation.
    """
    last_human = -1
    for index, message in enumerate(messages):
        if getattr(message, "type", "") == "human":
            last_human = index
    return list(messages[last_human + 1 :])


def _feedback_count(messages: Sequence[AnyMessage]) -> int:
    """Count regeneration rounds already spent on the current user request.

    Only evaluator-injected feedback messages *after* the last genuine human
    turn count, so the retry budget resets for every new user request.
    """
    last_genuine = -1
    for index, message in enumerate(messages):
        if (
            getattr(message, "type", "") == "human"
            and getattr(message, "name", None) != EVALUATOR_FEEDBACK_NAME
        ):
            last_genuine = index
    return sum(
        1
        for message in messages[last_genuine + 1 :]
        if getattr(message, "type", "") == "human"
        and getattr(message, "name", None) == EVALUATOR_FEEDBACK_NAME
    )


def _last_specialist(messages: Sequence[AnyMessage], names: frozenset[str]) -> str | None:
    """Return the name of the specialist whose answer most recently landed."""
    for message in reversed(messages):
        if getattr(message, "type", "") == "ai":
            name = getattr(message, "name", None)
            if name in names:
                return str(name)
    return None


def _final_answer(hop: Sequence[AnyMessage]) -> str:
    """Return the specialist's final answer text (last AI message, no tool calls)."""
    for message in reversed(hop):
        if getattr(message, "type", "") == "ai" and not (
            getattr(message, "tool_calls", None) or []
        ):
            text = message_text(message).strip()
            if text:
                return text
    return ""


def _tool_status_by_id(hop: Sequence[AnyMessage]) -> dict[str, str | None]:
    """Map each tool-call id in the hop to its result ``ToolMessage`` status."""
    status: dict[str, str | None] = {}
    for message in hop:
        if getattr(message, "type", "") == "tool":
            call_id = getattr(message, "tool_call_id", None)
            if call_id:
                status[str(call_id)] = getattr(message, "status", None)
    return status


def _parse_json(text: str) -> Any:
    """Best-effort JSON parse; return ``None`` when the text is not JSON."""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _result_reports(
    message: AnyMessage, *, spl_denylist: Sequence[str] | None
) -> list[tuple[str, LintReport]]:
    """Lint artifacts embedded in a successful tool result message."""
    name = getattr(message, "name", None)
    if name not in _RESULT_TOOLS or getattr(message, "status", None) == "error":
        return []
    payload = _parse_json(message_text(message))
    reports: list[tuple[str, LintReport]] = []
    if name == "convert_sigma_rule" and isinstance(payload, dict):
        siem = str(payload.get("siem", ""))
        queries = payload.get("queries")
        if isinstance(queries, list):
            for query in queries:
                if isinstance(query, str) and query.strip():
                    reports.append(
                        (f"converted:{siem or 'query'}", lint_query(query, siem, spl_denylist=spl_denylist))
                    )
    elif name == "export_navigator_layer" and isinstance(payload, (dict, str)):
        reports.append(("navigator", lint_navigator_layer(payload)))
    return reports


def _fenced_reports(
    answer: str, *, spl_denylist: Sequence[str] | None
) -> list[tuple[str, LintReport]]:
    """Lint query/rule artifacts fenced in the specialist's final answer."""
    reports: list[tuple[str, LintReport]] = []
    for raw_lang, raw_body in _FENCE_RE.findall(answer):
        lang = raw_lang.lower()
        body = raw_body.strip()
        if not body:
            continue
        if lang in _SPL_LANGS:
            reports.append(("answer:spl", lint_spl(body, denylist=spl_denylist or None)))
        elif lang in _SIGMA_LANGS or (
            lang == "yaml" and "detection:" in body and "logsource:" in body
        ):
            reports.append(("answer:sigma", lint_sigma(body)))
        elif lang in _LUCENE_LANGS:
            reports.append(("answer:lucene", lint_lucene(body)))
    return reports


def _collect_reports(
    hop: Sequence[AnyMessage], *, settings: Settings
) -> list[tuple[str, LintReport]]:
    """Lint everything the specialist actually produced in this hop."""
    protected = tuple(settings.sigma.protected_branches)
    spl_denylist = list(settings.agent.spl_denylist) or None
    status_by_id = _tool_status_by_id(hop)
    reports: list[tuple[str, LintReport]] = []
    for message in hop:
        kind = getattr(message, "type", "")
        if kind == "ai":
            for call in getattr(message, "tool_calls", None) or []:
                if not isinstance(call, dict):
                    continue
                # Skip calls that did not take effect (refused by the lint
                # middleware or failed at the backend): the agent has already
                # been told and self-corrects, so re-linting them only loops.
                if status_by_id.get(str(call.get("id"))) == "error":
                    continue
                report = lint_tool_input(
                    str(call.get("name", "")),
                    call.get("args") or {},
                    protected_branches=protected,
                    spl_denylist=spl_denylist,
                )
                if report is not None:
                    reports.append((f"tool:{call.get('name')}", report))
        elif kind == "tool":
            reports.extend(_result_reports(message, spl_denylist=spl_denylist))
    answer = _final_answer(hop)
    if answer:
        reports.extend(_fenced_reports(answer, spl_denylist=spl_denylist))
    return reports


def _hop_summary(hop: Sequence[AnyMessage]) -> str:
    """Render a compact, bounded summary of the hop for the LLM judge."""
    tools: list[str] = []
    for message in hop:
        if getattr(message, "type", "") == "ai":
            for call in getattr(message, "tool_calls", None) or []:
                if isinstance(call, dict) and call.get("name"):
                    tools.append(str(call["name"]))
    parts: list[str] = []
    if tools:
        parts.append("Tools used: " + ", ".join(dict.fromkeys(tools)))
    answer = _final_answer(hop)
    if answer:
        parts.append("Final answer:\n" + answer[:1500])
    return "\n\n".join(parts) or "(no output produced)"


async def _run_judge(model: BaseChatModel, *, specialist_title: str, hop_summary: str) -> str | None:
    """Ask the optional LLM judge for a second opinion.

    Returns a one-line revision reason when the judge votes to revise, or
    ``None`` to pass. The judge is best-effort: any failure passes so a flaky
    local model can never block an otherwise-clean turn.
    """
    try:
        reply = await model.ainvoke(
            [
                SystemMessage(content=_JUDGE_SYSTEM),
                HumanMessage(
                    content=f"Specialist: {specialist_title}\n\nTheir output:\n{hop_summary}"
                ),
            ]
        )
    except Exception:  # judge is advisory; a flaky model must never break the turn
        return None
    text = message_text(reply).strip()
    if text.upper().startswith("REVISE"):
        _, _, reason = text.partition(":")
        return reason.strip() or "The reviewer asked for another attempt."
    return None


def _critique_message(
    blocking: Sequence[tuple[str, LintFinding]],
    advisory: Sequence[tuple[str, LintFinding]],
    judge_reason: str | None,
) -> str:
    """Build the regeneration feedback handed back to the specialist."""
    lines = [
        "Automated review of your last response found problems that must be "
        "fixed before it can be accepted. Revise and resubmit, addressing every "
        "item below:",
    ]
    lines += [f"- ({label}) {item.message}" for label, item in blocking]
    if judge_reason:
        lines.append(f"- (reviewer) {judge_reason}")
    if advisory:
        lines.append("Also consider these non-blocking notes:")
        lines += [f"  - ({label}) {item.message}" for label, item in advisory]
    lines.append(
        "Do not repeat the rejected output verbatim. Produce a corrected version "
        "with no forbidden SPL commands, valid query/rule syntax, and real UUIDs."
    )
    return "\n".join(lines)


def _escalation_note(
    specialist_title: str,
    blocking: Sequence[tuple[str, LintFinding]],
    judge_reason: str | None,
) -> str:
    """Build the note surfaced to the human when the retry budget is spent."""
    lines = [
        f"Note: the {specialist_title} could not clear all automated-review "
        "issues within the retry budget. The latest output is shown above; the "
        "unresolved problems are:",
    ]
    lines += [f"- ({label}) {item.message}" for label, item in blocking]
    if judge_reason:
        lines.append(f"- (reviewer) {judge_reason}")
    return "\n".join(lines)


def make_evaluator_node(
    model: BaseChatModel,
    specialists: Sequence[SpecialistSpec],
    *,
    settings: Settings,
    audit: AuditLog,
) -> EvaluatorNode:
    """Create the async evaluator node that vets each specialist hop."""
    names = frozenset(spec.name for spec in specialists)
    titles = {spec.name: spec.title for spec in specialists}
    max_retries = settings.agent.eval_max_retries
    judge_enabled = settings.agent.llm_judge_enabled

    async def evaluator(state: SupervisorState) -> dict[str, Any]:
        messages = state["messages"]
        specialist = _last_specialist(messages, names)
        if specialist is None:
            # No specialist output to judge (e.g. the supervisor finished
            # directly); nothing to do but hand control back.
            return {"eval_route": SUPERVISOR_TARGET}

        title = titles.get(specialist, specialist)
        hop = _hop_messages(messages)
        reports = _collect_reports(hop, settings=settings)
        blocking = [(label, item) for label, report in reports for item in report.blocking]
        advisory = [(label, item) for label, report in reports for item in report.advisory]

        judge_reason: str | None = None
        if judge_enabled and not blocking:
            judge_reason = await _run_judge(
                model, specialist_title=title, hop_summary=_hop_summary(hop)
            )

        if blocking or judge_reason:
            attempts = _feedback_count(messages)
            issues = [item.code for _, item in blocking]
            if attempts >= max_retries:
                audit.record(
                    "eval_escalation",
                    specialist=specialist,
                    attempts=attempts,
                    issues=issues,
                )
                note = _escalation_note(title, blocking, judge_reason)
                return {
                    "messages": [AIMessage(content=note, name=EVALUATOR_NAME)],
                    "eval_route": SUPERVISOR_TARGET,
                }
            audit.record(
                "eval_regenerate",
                specialist=specialist,
                attempt=attempts + 1,
                issues=issues,
            )
            critique = _critique_message(blocking, advisory, judge_reason)
            return {
                "messages": [HumanMessage(content=critique, name=EVALUATOR_FEEDBACK_NAME)],
                "eval_route": specialist,
            }

        if advisory:
            audit.record(
                "eval_advisory",
                specialist=specialist,
                issues=[item.code for _, item in advisory],
            )
        return {"eval_route": SUPERVISOR_TARGET}

    return evaluator
