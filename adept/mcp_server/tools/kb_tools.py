"""Knowledge-base tools exposed over MCP.

These back retrieval-augmented rule authoring and tuning: the agent can search
the local detection knowledge corpus (own rules, ATT&CK techniques, homelab
docs, tuning history, and optional SigmaHQ rules) for grounding context.
Ingestion is performed out-of-band via the ``adept-kb`` CLI.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from adept.mcp_server.context import AppContext
from adept.mcp_server.tools._annotations import READ_ONLY
from adept.shared.errors import AdeptError


def register_kb_tools(mcp: FastMCP, ctx: AppContext) -> None:
    """Register the knowledge-base retrieval tools on the server."""

    @mcp.tool(title="Search the detection knowledge base", annotations=READ_ONLY)
    def search_knowledge_base(
        query: str,
        limit: int = 5,
        sources: list[str] | None = None,
    ) -> dict[str, object]:
        """Semantically search the local detection knowledge base.

        Returns the most relevant documents (Sigma rules, ATT&CK technique
        descriptions, homelab architecture notes, tuning history, and optional
        SigmaHQ rules) to ground rule authoring and tuning. Optionally restrict
        to specific ``sources`` (own_rules, attack, homelab, tuning, sigmahq).
        """
        try:
            result = ctx.knowledge_base().search(query, n_results=limit, sources=sources)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()

    @mcp.tool(title="Knowledge base status", annotations=READ_ONLY)
    def knowledge_base_status() -> dict[str, object]:
        """Report the knowledge-base collection name and indexed document count."""
        try:
            count = ctx.knowledge_base().count()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return {
            "collection": ctx.settings.kb.collection,
            "embed_model": ctx.settings.kb.embed_model,
            "documents": count,
        }
