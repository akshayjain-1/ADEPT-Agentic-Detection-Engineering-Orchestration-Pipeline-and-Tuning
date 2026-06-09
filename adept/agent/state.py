"""LangGraph state shared by the ADEPT supervisor graph."""

from __future__ import annotations

from typing import Annotated, NotRequired, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


class SupervisorState(TypedDict):
    """Conversation messages plus the supervisor's routing decision.

    ``messages`` uses the ``add_messages`` reducer, so node updates append to
    the running transcript. ``next`` holds the name of the specialist that the
    supervisor selected to run next, or the sentinel ``"FINISH"``.

    ``route_override`` is an optional, one-shot user instruction (set from an
    ``@specialist`` mention) that pins the *next* routing hop to a named
    specialist; the supervisor consumes it and clears it so subsequent hops
    route normally.
    """

    messages: Annotated[list[AnyMessage], add_messages]
    next: str
    route_override: NotRequired[str]
