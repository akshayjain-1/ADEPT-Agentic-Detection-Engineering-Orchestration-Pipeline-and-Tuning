"""Smoke tests: the MCP server builds and registers tools/resources."""

from __future__ import annotations

from pathlib import Path

import pytest
from adept.config.settings import Settings
from adept.mcp_server.server import build_server


def _settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("ADEPT_SIGMA__PATH", str(tmp_path / "sigma"))
    monkeypatch.setenv("ADEPT_DOCS_DIR", str(tmp_path / "docs"))
    monkeypatch.setenv("ADEPT_DATA_DIR", str(tmp_path / "data"))
    return Settings(_env_file=None)  # type: ignore[call-arg]


async def test_build_server_registers_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mcp = build_server(_settings(tmp_path, monkeypatch))
    names = {t.name for t in await mcp.list_tools()}
    assert {
        "list_sigma_rules",
        "read_sigma_rule",
        "write_sigma_rule",
        "git_create_branch",
        "git_commit",
        "git_diff",
        "git_status",
        "siem_list_backends",
        "siem_search",
        "siem_validate_query",
        "siem_get_fields",
        "siem_deploy_rule",
        "siem_disable_rule",
        "siem_delete_rule",
        "siem_list_alerts",
        "convert_sigma_rule",
        "validate_sigma_rule",
        "list_conversion_targets",
        "run_rule_unit_tests",
        "backtest_sigma_rule",
        "lookup_cve",
        "search_cves",
        "get_kev",
        "get_attack_technique",
        "fetch_security_news",
        "build_coverage_matrix",
        "export_navigator_layer",
        "identify_coverage_gaps",
        "find_rule_overlaps",
        "profile_field_baseline",
        "dettect_generate_layer",
        "search_knowledge_base",
        "knowledge_base_status",
        "list_atomic_tests",
        "plan_atomic_test",
        "list_caldera_adversaries",
        "list_caldera_agents",
        "list_caldera_operations",
        "get_caldera_operation_report",
        "run_caldera_operation",
        "stop_caldera_operation",
    } <= names


async def test_tools_carry_risk_annotations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every tool must expose MCP risk annotations so the agent's approval gate
    # can derive what is state-changing from the server (the single source of
    # truth) instead of a drift-prone client-side denylist.
    mcp = build_server(_settings(tmp_path, monkeypatch))
    tools = {t.name: t for t in await mcp.list_tools()}

    assert all(t.annotations is not None for t in tools.values())

    destructive = {
        "siem_deploy_rule",
        "siem_disable_rule",
        "siem_delete_rule",
        "run_caldera_operation",
        "stop_caldera_operation",
    }
    for name in destructive:
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.destructiveHint is True
        assert annotations.readOnlyHint is False

    low_risk_writes = {"write_sigma_rule", "git_create_branch", "git_commit"}
    for name in low_risk_writes:
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.readOnlyHint is False
        assert annotations.destructiveHint is False

    read_only = {
        "siem_search",
        "list_sigma_rules",
        "read_sigma_rule",
        "git_diff",
        "git_status",
        "convert_sigma_rule",
        "lookup_cve",
        "build_coverage_matrix",
        "search_knowledge_base",
        "list_atomic_tests",
    }
    for name in read_only:
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.readOnlyHint is True


async def test_build_server_registers_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mcp = build_server(_settings(tmp_path, monkeypatch))
    uris = {str(r.uri) for r in await mcp.list_resources()}
    assert "ade://taxonomy" in uris
    assert "sigma://schema" in uris
    assert "siem://targets" in uris


async def test_server_initialises_sigma_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_server(_settings(tmp_path, monkeypatch))
    assert (tmp_path / "sigma" / ".git").exists()
    assert (tmp_path / "sigma" / "rules").exists()
