"""Tests for the git-backed Sigma repository."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from adept.mcp_server.sigma_repo import SigmaRepo, derive_rule_path
from adept.shared.errors import SecurityError, ValidationFailedError

RULE = """\
title: Test Rule
id: 11111111-1111-4111-8111-111111111111
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\evil.exe'
  condition: selection
level: high
"""


def _repo(tmp_path: Path) -> SigmaRepo:
    repo = SigmaRepo(tmp_path / "sigma", default_branch="main", protected_branches=("main",))
    r = repo.ensure_repo()
    r.config_writer().set_value("user", "name", "Test").release()
    r.config_writer().set_value("user", "email", "test@example.com").release()
    return repo


def test_init_sets_default_branch(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    assert repo.current_branch() == "main"
    assert (repo.root / ".git").exists()


def test_write_read_and_list(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    rel = repo.write_rule("windows/process_creation/test.yml", RULE)
    assert rel == "rules/windows/process_creation/test.yml"
    assert "Test Rule" in repo.read_rule(rel)

    refs = repo.list_rules()
    assert len(refs) == 1
    assert refs[0].id == "11111111-1111-4111-8111-111111111111"
    assert refs[0].product == "windows"
    assert refs[0].category == "process_creation"
    assert refs[0].level == "high"


def test_path_traversal_blocked(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(SecurityError):
        repo.read_rule("../../etc/passwd")
    with pytest.raises(SecurityError):
        repo.write_rule("../escape.yml", RULE)


def test_non_yaml_rejected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(SecurityError):
        repo.write_rule("windows/x.txt", RULE)


def test_invalid_yaml_rejected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(ValidationFailedError):
        repo.write_rule("windows/bad.yml", "key: : : not yaml")


def test_protected_branch_commit_refused(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.write_rule("windows/process_creation/test.yml", RULE)
    with pytest.raises(SecurityError):
        repo.commit(["windows/process_creation/test.yml"], "add rule")


def test_branch_commit_and_diff(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.write_rule("windows/process_creation/test.yml", RULE)
    # First commit must go onto a feature branch (main is protected, unborn HEAD).
    repo.create_branch("feature/test", checkout=True)
    sha = repo.commit(["windows/process_creation/test.yml"], "add rule")
    assert len(sha) == 40
    assert repo.current_branch() == "feature/test"
    assert "feature/test" in repo.list_branches()


# --- SigmaHQ-style filename derivation ---------------------------------------


def _rule(title: str, **logsource: str) -> str:
    """Build a minimal valid Sigma rule with the given title + logsource."""
    ls = "\n".join(f"  {k}: {v}" for k, v in logsource.items())
    return (
        f"title: {title}\n"
        "id: 11111111-1111-4111-8111-111111111111\n"
        "logsource:\n"
        f"{ls}\n"
        "detection:\n"
        "  selection:\n"
        "    Image|endswith: '\\\\evil.exe'\n"
        "  condition: selection\n"
        "level: high\n"
    )


@pytest.mark.parametrize(
    ("title", "logsource", "expected"),
    [
        (
            "Whoami.EXE Execution",
            {"category": "process_creation", "product": "windows"},
            "windows/process_creation/proc_creation_win_whoami_exe_execution.yml",
        ),
        (
            "Suspicious Run Key",
            {"category": "registry_set", "product": "windows"},
            "windows/registry/registry_set/registry_set_win_suspicious_run_key.yml",
        ),
        (
            "Account Discovery",
            {"service": "security", "product": "windows"},
            "windows/builtin/security/win_security_account_discovery.yml",
        ),
        (
            "Curl Download",
            {"category": "process_creation", "product": "linux"},
            "linux/process_creation/proc_creation_lnx_curl_download.yml",
        ),
    ],
)
def test_derive_rule_path_follows_sigmahq_convention(
    title: str, logsource: dict[str, str], expected: str
) -> None:
    doc = yaml.safe_load(_rule(title, **logsource))
    assert derive_rule_path(doc) == expected


def test_derive_rule_path_requires_title() -> None:
    doc = yaml.safe_load(_rule("   ", category="process_creation", product="windows"))
    with pytest.raises(ValidationFailedError):
        derive_rule_path(doc)


def test_derive_rule_path_requires_logsource() -> None:
    with pytest.raises(ValidationFailedError):
        derive_rule_path({"title": "No Logsource"})


def test_write_derived_rule_names_file_from_content(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    rel = repo.write_derived_rule(_rule("Mimikatz Access", category="process_creation", product="windows"))
    assert rel == "rules/windows/process_creation/proc_creation_win_mimikatz_access.yml"
    assert "Mimikatz Access" in repo.read_rule(rel)


def test_write_derived_rule_is_idempotent(tmp_path: Path) -> None:
    # The same rule resolves to one deterministic path, so re-writing updates it
    # in place instead of scattering duplicate files (regression: placeholder
    # UUID filenames produced multiple files for a single rule).
    repo = _repo(tmp_path)
    repo.write_derived_rule(_rule("Net User Add", category="process_creation", product="windows"))
    repo.write_derived_rule(_rule("Net User Add", category="process_creation", product="windows"))
    refs = repo.list_rules()
    assert len(refs) == 1


def test_write_derived_rule_rejects_multi_document_yaml(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    rule = _rule("Doc One", category="process_creation", product="windows")
    with pytest.raises(ValidationFailedError):
        repo.write_derived_rule(rule + "---\n" + rule)

