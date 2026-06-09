"""Load tools from the remote ADEPT MCP server over streamable HTTP."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool
    from langchain_mcp_adapters.sessions import StreamableHttpConnection

    from adept.config.settings import Settings

SERVER_NAME = "adept"


def build_connection(settings: Settings) -> StreamableHttpConnection:
    """Build the streamable-HTTP connection mapping for the MCP server."""
    connection: StreamableHttpConnection = {
        "transport": "streamable_http",
        "url": settings.agent.mcp_url,
        "timeout": timedelta(seconds=settings.agent.mcp_timeout_seconds),
    }
    if settings.agent.mcp_token:
        connection["headers"] = {"Authorization": f"Bearer {settings.agent.mcp_token}"}
    return connection


async def load_tools(settings: Settings) -> list[BaseTool]:
    """Connect to the MCP server and return its tools as LangChain tools."""
    from langchain_mcp_adapters.client import MultiServerMCPClient

    client = MultiServerMCPClient({SERVER_NAME: build_connection(settings)})
    return await client.get_tools()
