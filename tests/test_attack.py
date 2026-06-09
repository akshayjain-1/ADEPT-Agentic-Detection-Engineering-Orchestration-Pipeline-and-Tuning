"""Offline tests for the attack-simulation package.

Atomic tests run against a tiny temporary atomic-red-team tree; Caldera tests
use an httpx ``MockTransport`` so nothing touches the network. No Ollama, MCP
server, or live Caldera instance is required.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml
from adept.attack.atomic import AtomicLibrary
from adept.attack.caldera import CalderaClient
from adept.config.settings import AttackSimSettings
from adept.shared.errors import (
    BackendNotEnabledError,
    ConfigurationError,
    SecurityError,
    ToolExecutionError,
)

# --------------------------------------------------------------------------- #
# Atomic Red Team (propose-only)                                              #
# --------------------------------------------------------------------------- #

_ATOMIC_DOC = {
    "attack_technique": "T1059.001",
    "display_name": "Command and Scripting Interpreter: PowerShell",
    "atomic_tests": [
        {
            "name": "Dump credentials",
            "auto_generated_guid": "11111111-1111-1111-1111-111111111111",
            "description": "Dump credentials via PowerShell.\n",
            "supported_platforms": ["windows"],
            "input_arguments": {
                "output_file": {
                    "description": "output path",
                    "type": "path",
                    "default": "default_out.txt",
                },
            },
            "dependencies": [
                {
                    "description": "PowerShell must be available",
                    "prereq_command": "echo ok",
                    "get_prereq_command": "echo install",
                },
            ],
            "executor": {
                "name": "powershell",
                "elevation_required": True,
                "command": "Invoke-Mimikatz > #{output_file}\n",
                "cleanup_command": "Remove-Item #{output_file}\n",
            },
        },
        {
            "name": "Manual step test",
            "auto_generated_guid": "22222222-2222-2222-2222-222222222222",
            "description": "manual",
            "supported_platforms": ["linux"],
            "executor": {"name": "manual", "command": "", "steps": "Do #{thing}\n"},
        },
    ],
}


def _atomic_tree(tmp_path: Path) -> Path:
    technique_dir = tmp_path / "atomics" / "T1059.001"
    technique_dir.mkdir(parents=True)
    (technique_dir / "T1059.001.yaml").write_text(yaml.safe_dump(_ATOMIC_DOC), encoding="utf-8")
    return tmp_path


def _atomic_lib(tmp_path: Path, **overrides: object) -> AtomicLibrary:
    kwargs: dict[str, object] = {
        "atomic_enabled": True,
        "atomic_path": str(tmp_path),
        "atomic_allowed_tests": ["T1059.001"],
    }
    kwargs.update(overrides)
    settings = AttackSimSettings(**kwargs)  # type: ignore[arg-type]
    return AtomicLibrary.from_settings(settings)


def test_atomic_list_tests(tmp_path: Path) -> None:
    lib = _atomic_lib(_atomic_tree(tmp_path))
    listing = lib.list_tests("T1059.001")
    assert listing.technique == "T1059.001"
    assert listing.display_name.startswith("Command and Scripting")
    assert listing.total == 2
    assert listing.tests[0].name == "Dump credentials"
    assert listing.tests[0].guid == "11111111-1111-1111-1111-111111111111"
    assert listing.tests[0].supported_platforms == ["windows"]
    assert listing.tests[0].executor_name == "powershell"


def test_atomic_plan_substitutes_default(tmp_path: Path) -> None:
    lib = _atomic_lib(_atomic_tree(tmp_path))
    plan = lib.plan_test("T1059.001")
    assert plan.name == "Dump credentials"
    assert "default_out.txt" in plan.command
    assert "default_out.txt" in plan.cleanup_command
    assert plan.elevation_required is True
    assert plan.executor_name == "powershell"
    assert plan.dependencies == ["PowerShell must be available"]
    assert plan.note.startswith("PROPOSE-ONLY")
    assert plan.arguments["output_file"] == "default_out.txt"


def test_atomic_plan_argument_override(tmp_path: Path) -> None:
    lib = _atomic_lib(_atomic_tree(tmp_path))
    plan = lib.plan_test("T1059.001", arguments={"output_file": "custom.txt"})
    assert "custom.txt" in plan.command
    assert "default_out.txt" not in plan.command


def test_atomic_plan_select_by_index_name_and_guid(tmp_path: Path) -> None:
    lib = _atomic_lib(_atomic_tree(tmp_path))
    by_index = lib.plan_test("T1059.001", test="2")
    assert by_index.name == "Manual step test"
    assert by_index.executor_name == "manual"
    # Unresolved placeholders for absent arguments are preserved verbatim.
    assert "#{thing}" in by_index.manual_steps
    assert lib.plan_test("T1059.001", test="Manual step").name == "Manual step test"
    assert (
        lib.plan_test("T1059.001", test="22222222-2222-2222-2222-222222222222").name
        == "Manual step test"
    )


def test_atomic_disabled_raises(tmp_path: Path) -> None:
    settings = AttackSimSettings(atomic_enabled=False, atomic_path=str(_atomic_tree(tmp_path)))
    lib = AtomicLibrary.from_settings(settings)
    with pytest.raises(BackendNotEnabledError):
        lib.list_tests("T1059.001")


def test_atomic_not_allowlisted_raises(tmp_path: Path) -> None:
    settings = AttackSimSettings(
        atomic_enabled=True,
        atomic_path=str(_atomic_tree(tmp_path)),
        atomic_allowed_tests=["T1003.001"],
    )
    lib = AtomicLibrary.from_settings(settings)
    with pytest.raises(SecurityError):
        lib.list_tests("T1059.001")


def test_atomic_invalid_technique_id_raises(tmp_path: Path) -> None:
    lib = _atomic_lib(_atomic_tree(tmp_path))
    with pytest.raises(ToolExecutionError):
        lib.list_tests("not-a-technique")


def test_atomic_missing_path_raises(tmp_path: Path) -> None:
    settings = AttackSimSettings(
        atomic_enabled=True, atomic_path="", atomic_allowed_tests=["T1059.001"]
    )
    lib = AtomicLibrary.from_settings(settings)
    with pytest.raises(ConfigurationError):
        lib.list_tests("T1059.001")


def test_atomic_missing_technique_file_raises(tmp_path: Path) -> None:
    lib = _atomic_lib(_atomic_tree(tmp_path), atomic_allowed_tests=[])
    with pytest.raises(ToolExecutionError):
        lib.list_tests("T1059.002")


# --------------------------------------------------------------------------- #
# Caldera v2 REST client                                                      #
# --------------------------------------------------------------------------- #


def _caldera_client(handler: httpx.MockTransport) -> CalderaClient:
    client = CalderaClient(
        base_url="http://caldera.local/api/v2",
        api_key="k",
        enabled=True,
    )
    client._client = httpx.Client(transport=handler, headers={client.header_name: client.api_key})
    return client


def _make_handler(captured: dict[str, object]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("KEY") == "k"
        path = request.url.path
        method = request.method
        if method == "GET" and path == "/api/v2/adversaries":
            return httpx.Response(
                200, json=[{"adversary_id": "a1", "name": "APT-X", "description": "d"}]
            )
        if method == "GET" and path == "/api/v2/agents":
            return httpx.Response(
                200,
                json=[
                    {
                        "paw": "p1",
                        "host": "h1",
                        "platform": "windows",
                        "group": "red",
                        "trusted": True,
                    }
                ],
            )
        if method == "GET" and path == "/api/v2/operations":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "op1",
                        "name": "Op One",
                        "state": "running",
                        "adversary": {"name": "APT-X"},
                        "start": "2024-01-01",
                    }
                ],
            )
        if method == "POST" and path == "/api/v2/operations/op1/report":
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "id": "op1",
                    "name": "Op One",
                    "state": "finished",
                    "agent_output": body["enable_agent_output"],
                },
            )
        if method == "POST" and path == "/api/v2/operations":
            body = json.loads(request.content)
            captured["create_body"] = body
            return httpx.Response(
                200,
                json={
                    "id": "op2",
                    "name": body["name"],
                    "state": "running",
                    "adversary": {"name": "APT-X"},
                    "start": "2024-01-02",
                },
            )
        if method == "PATCH" and path == "/api/v2/operations/op1":
            body = json.loads(request.content)
            captured["patch_body"] = body
            return httpx.Response(
                200,
                json={
                    "id": "op1",
                    "name": "Op One",
                    "state": body["state"],
                    "adversary": {"name": "APT-X"},
                    "start": "2024-01-01",
                },
            )
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


def test_caldera_list_adversaries() -> None:
    client = _caldera_client(_make_handler({}))
    adversaries = client.list_adversaries()
    assert len(adversaries) == 1
    assert adversaries[0].adversary_id == "a1"
    assert adversaries[0].name == "APT-X"


def test_caldera_list_agents() -> None:
    client = _caldera_client(_make_handler({}))
    agents = client.list_agents()
    assert agents[0].paw == "p1"
    assert agents[0].platform == "windows"
    assert agents[0].group == "red"


def test_caldera_list_operations() -> None:
    client = _caldera_client(_make_handler({}))
    operations = client.list_operations()
    assert operations[0].id == "op1"
    assert operations[0].state == "running"
    assert operations[0].adversary == "APT-X"


def test_caldera_operation_report() -> None:
    client = _caldera_client(_make_handler({}))
    report = client.get_operation_report("op1", agent_output=True)
    assert report.id == "op1"
    assert report.state == "finished"
    assert report.report["agent_output"] is True


def test_caldera_create_operation_sends_expected_body() -> None:
    captured: dict[str, object] = {}
    client = _caldera_client(_make_handler(captured))
    summary = client.create_operation("My Op", "a1")
    assert summary.id == "op2"
    assert summary.name == "My Op"
    assert summary.state == "running"
    body = captured["create_body"]
    assert isinstance(body, dict)
    assert body["name"] == "My Op"
    assert body["adversary"] == {"adversary_id": "a1"}
    assert body["planner"] == {"id": "atomic"}
    assert body["source"] == {"id": "basic"}


def test_caldera_set_operation_state() -> None:
    captured: dict[str, object] = {}
    client = _caldera_client(_make_handler(captured))
    summary = client.set_operation_state("op1", "finished")
    assert summary.state == "finished"
    assert captured["patch_body"] == {"state": "finished"}


def test_caldera_disabled_raises() -> None:
    client = CalderaClient(base_url="http://x/api/v2", api_key="", enabled=False)
    with pytest.raises(BackendNotEnabledError):
        client.list_adversaries()


def test_caldera_missing_url_raises() -> None:
    client = CalderaClient(base_url="", api_key="", enabled=True)
    with pytest.raises(ConfigurationError):
        client.list_adversaries()


def test_caldera_non_http_scheme_raises() -> None:
    client = CalderaClient(base_url="ftp://x/api/v2", api_key="", enabled=True)
    with pytest.raises(SecurityError):
        client.list_adversaries()


def test_caldera_from_settings_builds_base_url() -> None:
    settings = AttackSimSettings(
        caldera_enabled=True,
        caldera_url="http://host:8888/",
        caldera_api_key="z",
    )
    client = CalderaClient.from_settings(settings)
    assert client.base_url == "http://host:8888/api/v2"
    assert client.header_name == "KEY"
    assert client.enabled is True
