"""Threat-intelligence tools exposed over MCP.

These back the Threat-Intel Researcher agent: CVE lookup and search (NVD), the
CISA Known Exploited Vulnerabilities catalogue, MITRE ATT&CK technique details,
and recent security news from configured feeds. Every source is cached and
restricted to an allowlist of hosts, so the tools are safe and fast to call
repeatedly.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from adept.mcp_server.context import AppContext
from adept.mcp_server.tools._annotations import READ_ONLY
from adept.shared.errors import AdeptError


def register_intel_tools(mcp: FastMCP, ctx: AppContext) -> None:
    """Register the threat-intelligence tools on the server."""
    intel = ctx.intel

    @mcp.tool(title="Look up a CVE", annotations=READ_ONLY)
    def lookup_cve(cve_id: str) -> dict[str, object]:
        """Look up a single CVE by id (e.g. ``CVE-2021-44228``) via the NVD.

        Returns the description, CVSS metrics, CWEs, references, and whether the
        CVE is on the CISA KEV catalogue.
        """
        try:
            return intel.nvd.lookup_cve(cve_id).model_dump()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Search CVEs by keyword", annotations=READ_ONLY)
    def search_cves(keyword: str, limit: int = 10) -> dict[str, object]:
        """Search the NVD for CVEs matching ``keyword`` (capped at 50 results)."""
        try:
            return intel.nvd.search_cves(keyword, limit=limit).model_dump()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Query the CISA KEV catalogue", annotations=READ_ONLY)
    def get_kev(
        cve_id: str | None = None,
        query: str | None = None,
        limit: int = 50,
    ) -> dict[str, object]:
        """Return CISA Known Exploited Vulnerabilities.

        Filter by ``cve_id`` for a single entry, by ``query`` for a free-text
        match across vendor/product/name/description, or omit both for the most
        recent additions (capped by ``limit``).
        """
        try:
            return intel.kev.get_kev(cve_id=cve_id, query=query, limit=limit).model_dump()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Get a MITRE ATT&CK technique", annotations=READ_ONLY)
    def get_attack_technique(attack_id: str) -> dict[str, object]:
        """Return details for an ATT&CK enterprise technique (e.g. ``T1003.001``).

        Includes the name, description, mapped tactics, platforms, and the
        canonical ATT&CK URL. The STIX bundle is downloaded once and cached.
        """
        try:
            return intel.attack.get_technique(attack_id).model_dump()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Fetch recent security news", annotations=READ_ONLY)
    def fetch_security_news(limit: int = 20) -> dict[str, object]:
        """Return recent items from the configured security RSS/Atom feeds."""
        try:
            return intel.news.fetch_security_news(limit=limit).model_dump()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
