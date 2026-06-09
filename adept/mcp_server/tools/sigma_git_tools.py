"""Sigma rule + git tools exposed over MCP.

These let the agent enumerate, read, and author Sigma rules, and manage branches,
commits, and diffs. State-changing git operations (commit) refuse protected
branches, keeping changes on feature branches for the human approval gate.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from adept.mcp_server.context import AppContext
from adept.mcp_server.tools._annotations import LOW_RISK_WRITE, READ_ONLY
from adept.shared.errors import AdeptError


def register_sigma_git_tools(mcp: FastMCP, ctx: AppContext) -> None:
    """Register Sigma-repository tools on the server."""
    repo = ctx.sigma_repo

    @mcp.tool(title="List Sigma rules", annotations=READ_ONLY)
    def list_sigma_rules(
        product: str | None = None,
        category: str | None = None,
        tag: str | None = None,
        level: str | None = None,
    ) -> list[dict[str, object]]:
        """List Sigma rules in the repository, optionally filtered.

        Args:
            product: Only rules whose logsource product matches (e.g. ``windows``).
            category: Only rules whose logsource category matches (e.g. ``process_creation``).
            tag: Only rules carrying this tag (e.g. ``attack.t1059``).
            level: Only rules with this severity level (e.g. ``high``).

        Returns a list of rule summaries (path, id, title, status, level,
        product, category, tags).
        """
        results: list[dict[str, object]] = []
        for ref in repo.list_rules():
            if product and ref.product != product:
                continue
            if category and ref.category != category:
                continue
            if level and ref.level != level:
                continue
            if tag and tag not in ref.tags:
                continue
            results.append(ref.model_dump())
        return results

    @mcp.tool(title="Read a Sigma rule", annotations=READ_ONLY)
    def read_sigma_rule(path: str) -> str:
        """Return the raw YAML of a Sigma rule by its repo-relative path."""
        try:
            return repo.read_rule(path)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Write a Sigma rule", annotations=LOW_RISK_WRITE)
    def write_sigma_rule(content: str) -> dict[str, object]:
        """Create or update a Sigma rule from its YAML content.

        Provide a single YAML document with a descriptive ``title`` and a real,
        unique ``id``. The server derives the filename from the rule's own
        ``title`` and ``logsource`` (the SigmaHQ naming convention), so you do not
        choose a path or filename yourself; writing the same rule again updates it
        in place. This does not commit; use ``git_create_branch`` and
        ``git_commit`` to persist the change on a feature branch. Returns the
        repo-relative path the server chose.
        """
        try:
            written = repo.write_derived_rule(content)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return {"path": written, "written": True}

    @mcp.tool(title="Create or switch git branch", annotations=LOW_RISK_WRITE)
    def git_create_branch(name: str) -> dict[str, object]:
        """Create (if needed) and check out a git branch in the rules repo."""
        try:
            repo.create_branch(name, checkout=True)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return {"branch": name, "current": repo.current_branch()}

    @mcp.tool(title="Commit rule changes", annotations=LOW_RISK_WRITE)
    def git_commit(paths: list[str], message: str) -> dict[str, object]:
        """Commit the given rule paths with a message.

        Refuses to commit to a protected branch (e.g. ``main``); create a feature
        branch first. Returns the commit SHA.
        """
        try:
            sha = repo.commit(paths, message)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return {"commit": sha, "branch": repo.current_branch(), "paths": list(paths)}

    @mcp.tool(title="Show git diff", annotations=READ_ONLY)
    def git_diff(ref: str | None = None) -> str:
        """Return the working-tree diff, or the diff against ``ref`` if given."""
        try:
            return repo.diff(ref=ref) or "(no changes)"
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Git repository status", annotations=READ_ONLY)
    def git_status() -> dict[str, object]:
        """Return the current branch and the list of branches."""
        return {
            "current_branch": repo.current_branch(),
            "branches": repo.list_branches(),
            "protected": sorted(repo.protected_branches),
        }
