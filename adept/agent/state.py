"""LangGraph state shared by the ADEPT supervisor graph."""

from __future__ import annotations

from typing import Annotated, NotRequired, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages

#: Name tag on a ``HumanMessage`` the evaluator injects to ask a specialist to
#: regenerate. The supervisor router ignores these turns so it keeps routing on
#: the real user request rather than on its own critique.
EVALUATOR_FEEDBACK_NAME = "evaluator_feedback"


class SupervisorState(TypedDict):
    """Conversation messages plus the supervisor's routing decision.

    ``messages`` uses the ``add_messages`` reducer, so node updates append to
    the running transcript. ``next`` holds the name of the specialist that the
    supervisor selected to run next, or the sentinel ``"FINISH"``.

    ``route_override`` is an optional, one-shot user instruction (set from an
    ``@specialist`` mention) that pins the *next* routing hop to a named
    specialist; the supervisor consumes it and clears it so subsequent hops
    route normally.

    ``eval_route`` is set by the evaluator node after it lints a specialist's
    output: the specialist's own name to send the work back for regeneration,
    or ``"supervisor"`` to proceed once the output passes (or retries are spent).
    """

    messages: Annotated[list[AnyMessage], add_messages]
    next: str
    route_override: NotRequired[str]
    eval_route: NotRequired[str]
