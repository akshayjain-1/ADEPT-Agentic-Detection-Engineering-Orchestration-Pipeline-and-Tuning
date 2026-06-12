"""Deterministic output guardrails (linters) for agent-generated artifacts.

These pure, offline linters vet what the LLM produces — SPL/Lucene queries,
Sigma YAML, Navigator layers, and git operations — so security- or
syntax-breaking output is caught before it is executed or proposed. They back
both the agent's evaluator node and the per-tool lint middleware, and depend
only on the detection-as-code domain package (never on the agent or MCP layers).
"""

from __future__ import annotations

from adept.guardrails.git import lint_git_branch, lint_git_commit
from adept.guardrails.lucene import lint_lucene
from adept.guardrails.models import LintFinding, LintReport, LintSeverity
from adept.guardrails.navigator import lint_navigator_layer
from adept.guardrails.registry import lint_query, lint_tool_input
from adept.guardrails.sigma import lint_sigma
from adept.guardrails.spl import DANGEROUS_SPL_COMMANDS, lint_spl

__all__ = [
    "DANGEROUS_SPL_COMMANDS",
    "LintFinding",
    "LintReport",
    "LintSeverity",
    "lint_git_branch",
    "lint_git_commit",
    "lint_lucene",
    "lint_navigator_layer",
    "lint_query",
    "lint_sigma",
    "lint_spl",
    "lint_tool_input",
]
