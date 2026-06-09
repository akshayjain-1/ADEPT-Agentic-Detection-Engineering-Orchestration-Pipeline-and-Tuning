"""ADEPT LangGraph multi-agent application.

A hybrid-supervisor graph routes a conversation between focused specialist
agents (hunt/intel, rule authoring, coverage, deployment, purple-teaming).
Specialists call MCP tools loaded from the ADEPT server; state-changing tools
are gated behind a human-in-the-loop approval step. Conversations persist in a
SQLite checkpointer.
"""

from __future__ import annotations

from adept.agent.approval import (
    ApprovalAction,
    ApprovalDecision,
    ApprovalRequest,
    guard_tool,
    guard_tools,
)
from adept.agent.audit import AuditLog
from adept.agent.history import list_threads, new_thread_id
from adept.agent.llm import build_chat_model
from adept.agent.mcp_client import build_connection, load_tools
from adept.agent.service import AgentSession, open_agent_session
from adept.agent.specialists import SPECIALISTS, SpecialistSpec
from adept.agent.state import SupervisorState
from adept.agent.supervisor import (
    FINISH,
    build_specialist_agents,
    build_supervisor_graph,
    make_supervisor_node,
    message_text,
)

__all__ = [
    "FINISH",
    "SPECIALISTS",
    "AgentSession",
    "ApprovalAction",
    "ApprovalDecision",
    "ApprovalRequest",
    "AuditLog",
    "SpecialistSpec",
    "SupervisorState",
    "build_chat_model",
    "build_connection",
    "build_specialist_agents",
    "build_supervisor_graph",
    "guard_tool",
    "guard_tools",
    "list_threads",
    "load_tools",
    "make_supervisor_node",
    "message_text",
    "new_thread_id",
    "open_agent_session",
]
