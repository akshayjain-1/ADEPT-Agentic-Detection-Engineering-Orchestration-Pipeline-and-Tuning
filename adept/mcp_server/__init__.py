"""ADEPT MCP server.

Exposes SIEM access, Sigma rule management, detection-as-code, threat
intelligence, coverage analysis, and adversary-emulation capabilities to the
agent over the Model Context Protocol (streamable HTTP transport).
"""

from __future__ import annotations

from adept.mcp_server.server import build_server, main

__all__ = ["build_server", "main"]
