"""Tests for the detection-as-code library: conversion, validation, matching,
unit-test harness, lifecycle metadata and backtest.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from adept.detection_as_code import (
    RuleValidator,
    SigmaConverter,
    backtest_rule,
    can_transition,
    evaluate_rule,
    load_metadata,
    run_test_file,
)
from adept.detection_as_code.pipelines import build_pipeline, default_pipelines
from adept.mcp_server.siem.models import SearchHit, SearchResult
from adept.shared.errors import ConfigurationError, SecurityError
from sigma.collection import SigmaCollection

REPO = Path(__file__).resolve().parents[1] / "sigma_rules"

WHOAMI_RULE = """
title: Whoami Execution
id: 75aab411-6c19-466c-81a7-c3ababbdc340
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\\\\whoami.exe'
    selection_ofn:
        OriginalFileName: 'whoami.exe'
    filter_dir:
        CommandLine|contains: 'dir '
    condition: (selection_img or selection_ofn) and not filter_dir
level: high
"""


def _rule() -> object:
    return SigmaCollection.from_yaml(WHOAMI_RULE).rules[0]


# --------------------------------------------------------------------------
# Conversion
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("siem", "needle"),
    [
        ("elk", "process.executable:*\\\\whoami.exe"),
        ("opensearch", "process.executable:*\\\\whoami.exe"),
        ("splunk", 'Image="*\\\\whoami.exe"'),
    ],
)
def test_convert_produces_expected_query(siem: str, needle: str) -> None:
    result = SigmaConverter().convert(WHOAMI_RULE, siem)
    assert result.siem == siem
    assert result.queries
    assert any(needle in query for query in result.queries)


def test_convert_unknown_siem_raises() -> None:
    with pytest.raises(ConfigurationError):
        SigmaConverter().convert(WHOAMI_RULE, "nope")


def test_default_pipelines_windows_vs_other() -> None:
    assert default_pipelines("elk", "windows") == ["sysmon", "ecs_windows"]
    assert default_pipelines("splunk", "windows") == ["sysmon", "splunk_windows"]
    assert default_pipelines("elk", "linux") == []


def test_build_pipeline_rejects_file_path_without_allowed_dir() -> None:
    # With no allowed directory only installed pipeline *names* are accepted; a
    # filesystem path must be refused without ever reading it.
    with pytest.raises(ConfigurationError):
        build_pipeline(["/etc/passwd"])


def test_build_pipeline_rejects_absolute_path_outside_allowed_dir(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        build_pipeline(["/etc/passwd"], allowed_dir=tmp_path)


def test_build_pipeline_rejects_parent_traversal(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        build_pipeline(["../escape.yml"], allowed_dir=tmp_path)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def test_validate_good_rule_ok() -> None:
    report = RuleValidator().validate_text(WHOAMI_RULE)
    assert report.rule_count == 1
    assert report.error_count == 0


def test_validate_unparseable_rule_reports_error() -> None:
    report = RuleValidator().validate_text("not: [a, valid: sigma")
    assert report.ok is False
    assert report.issues
    assert report.issues[0].severity == "high"


# --------------------------------------------------------------------------
# Event matcher
# --------------------------------------------------------------------------
def test_matcher_true_positive_endswith() -> None:
    rule = _rule()
    assert evaluate_rule(rule, {"Image": "C:\\Windows\\System32\\whoami.exe"}) is True


def test_matcher_true_positive_original_filename() -> None:
    rule = _rule()
    event = {"Image": "C:\\users\\public\\wm.exe", "OriginalFileName": "whoami.exe"}
    assert evaluate_rule(rule, event) is True


def test_matcher_false_positive_other_binary() -> None:
    rule = _rule()
    assert evaluate_rule(rule, {"Image": "C:\\Windows\\System32\\cmd.exe"}) is False


def test_matcher_not_filter_excludes() -> None:
    rule = _rule()
    event = {"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "dir foo"}
    assert evaluate_rule(rule, event) is False


def test_matcher_keyword_search() -> None:
    rule = SigmaCollection.from_yaml(
        """
title: kw
id: cb22f931-d7a5-41a5-968a-eb979218a781
status: test
logsource: {category: process_creation, product: windows}
detection:
    sel: ['mimikatz', 'sekurlsa']
    condition: sel
level: high
"""
    ).rules[0]
    assert evaluate_rule(rule, {"CommandLine": "run mimikatz.exe now"}) is True
    assert evaluate_rule(rule, {"CommandLine": "ipconfig /all"}) is False


def test_matcher_null_value() -> None:
    rule = SigmaCollection.from_yaml(
        """
title: nullparent
id: b9f02811-7258-4f74-aec0-900547605518
status: test
logsource: {category: process_creation, product: windows}
detection:
    sel: {Image|endswith: '\\\\svchost.exe', ParentImage: null}
    condition: sel
level: high
"""
    ).rules[0]
    assert evaluate_rule(rule, {"Image": "C:\\x\\svchost.exe"}) is True
    assert evaluate_rule(rule, {"Image": "C:\\x\\svchost.exe", "ParentImage": "x"}) is False


def test_matcher_case_insensitive_regex_flag() -> None:
    # A Sigma `|re|i` modifier must apply re.IGNORECASE so the offline matcher
    # agrees with the (case-insensitive) query deployed to the SIEM.
    rule = SigmaCollection.from_yaml(
        """
title: ci-regex
id: 6e6d3d4d-1f0d-4f8c-9a2b-2f3c4d5e6f70
status: test
logsource: {category: process_creation, product: windows}
detection:
    sel:
        CommandLine|re|i: 'mimikatz'
    condition: sel
level: high
"""
    ).rules[0]
    assert evaluate_rule(rule, {"CommandLine": "C:\\Tools\\MIMIKATZ.exe"}) is True
    assert evaluate_rule(rule, {"CommandLine": "benign.exe"}) is False


# --------------------------------------------------------------------------
# Unit-test harness (against the real repo test file)
# --------------------------------------------------------------------------
def test_run_repo_unit_tests_pass() -> None:
    test_file = REPO / "tests" / "proc_creation_win_whoami_discovery.yml"
    report = run_test_file(test_file, repo_root=REPO)
    assert report.ok is True
    assert report.failed == 0
    assert report.total == 4


# --------------------------------------------------------------------------
# Lifecycle metadata
# --------------------------------------------------------------------------
def test_load_repo_metadata_valid() -> None:
    meta_path = (
        REPO
        / "metadata"
        / "windows"
        / "process_creation"
        / "proc_creation_win_whoami_discovery.meta.yml"
    )
    meta = load_metadata(meta_path, REPO)
    assert meta["rule_id"] == "75aab411-6c19-466c-81a7-c3ababbdc340"
    assert meta["stage"] in {"draft", "testing", "production", "deprecated", "disabled"}


def test_stage_transitions() -> None:
    assert can_transition("draft", "testing") is True
    assert can_transition("testing", "production") is True
    assert can_transition("production", "draft") is False
    assert can_transition("deprecated", "production") is False


# --------------------------------------------------------------------------
# Backtest (with a fake backend)
# --------------------------------------------------------------------------
class _FakeBackend:
    siem_id = "elk"

    def __init__(self, total: int) -> None:
        self._total = total
        self.captured: dict[str, object] = {}

    def search(
        self,
        query: str,
        *,
        index: str | None = None,
        size: int = 50,
        earliest: str | None = None,
        latest: str | None = None,
    ) -> SearchResult:
        self.captured = {"query": query, "index": index, "earliest": earliest}
        hits = [SearchHit(source={"i": i}) for i in range(min(size, self._total))]
        return SearchResult(backend=self.siem_id, index=index or "", total=self._total, hits=hits)


def test_backtest_estimates_daily_volume() -> None:
    backend = _FakeBackend(total=70)
    result = backtest_rule(
        WHOAMI_RULE,
        backend,  # type: ignore[arg-type]
        index="logs-*",
        lookback_days=7,
    )
    assert result.matches == 70
    assert result.estimated_daily_volume == 10.0
    assert result.sampled is True
    assert backend.captured["earliest"] == "now-7d"
    assert "process.executable" in str(backend.captured["query"])
