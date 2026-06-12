"""Dispatch helpers that map a SIEM/query/tool to the right linter."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from adept.detection_as_code.targets import SIEM_QUERY_LANGUAGE
from adept.guardrails.git import lint_git_branch, lint_git_commit
from adept.guardrails.lucene import lint_lucene
from adept.guardrails.models import LintReport
from adept.guardrails.sigma import lint_sigma
from adept.guardrails.spl import lint_spl

#: Tools whose query argument carries a SIEM search the linter must vet.
_QUERY_TOOLS = frozenset({"siem_search", "siem_validate_query", "siem_deploy_rule"})


def lint_query(query: str, siem: str, *, spl_denylist: Collection[str] | None = None) -> LintReport:
    """Lint a SIEM query, picking SPL vs Lucene from the SIEM id."""
    language = SIEM_QUERY_LANGUAGE.get(siem, "").upper()
    if siem == "splunk" or language == "SPL":
        return lint_spl(query, denylist=spl_denylist or None)
    return lint_lucene(query)


def lint_tool_input(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    protected_branches: Collection[str] = (),
    spl_denylist: Collection[str] | None = None,
) -> LintReport | None:
    """Lint a tool call's arguments; return ``None`` when the tool isn't lintable."""
    if tool_name in _QUERY_TOOLS:
        query = args.get("query")
        if isinstance(query, str):
            return lint_query(query, str(args.get("backend", "")), spl_denylist=spl_denylist)
        return None
    if tool_name == "write_sigma_rule":
        content = args.get("content")
        return lint_sigma(content) if isinstance(content, str) else None
    if tool_name == "git_create_branch":
        name = args.get("name")
        return lint_git_branch(name, protected=protected_branches) if isinstance(name, str) else None
    if tool_name == "git_commit":
        message = args.get("message")
        return lint_git_commit(message) if isinstance(message, str) else None
    return None
