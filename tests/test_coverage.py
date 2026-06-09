"""Offline tests for the ATT&CK coverage package.

All tests use a lightweight fake catalogue (:meth:`AttackCatalog.from_techniques`)
and a fake SIEM backend, so they never load the 53MB STIX bundle or touch a live
SIEM.
"""

from __future__ import annotations

from pathlib import Path

from adept.config.settings import CoverageSettings
from adept.coverage import (
    AttackCatalog,
    RuleInfo,
    TechniqueMeta,
    build_coverage_matrix,
    build_navigator_layer,
    extract_attack_tags,
    find_overlaps,
    generate_layer,
    identify_gaps,
    is_available,
    load_rules,
    profile_fields,
)
from adept.coverage.dettect import _resolve_command
from adept.mcp_server.siem._lucene import build_terms_aggregation, parse_terms_aggregation
from adept.mcp_server.siem.models import FieldAggregation

# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
_RULE_YAML = """
title: Whoami Execution
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \\whoami.exe
    condition: selection
tags:
    - attack.discovery
    - attack.t1033
"""


def _catalog() -> AttackCatalog:
    return AttackCatalog.from_techniques(
        [
            TechniqueMeta("T1033", "System Owner/User Discovery", ("discovery",), ("Windows",)),
            TechniqueMeta("T1003", "OS Credential Dumping", ("credential-access",), ("Windows",)),
            TechniqueMeta(
                "T1003.001",
                "LSASS Memory",
                ("credential-access",),
                ("Windows",),
                is_subtechnique=True,
            ),
            TechniqueMeta(
                "T1595.001",
                "Scanning IP Blocks",
                ("reconnaissance",),
                ("PRE",),
                is_subtechnique=True,
            ),
        ]
    )


def _rule(
    rule_id: str,
    technique_ids: set[str],
    *,
    product: str = "windows",
    category: str = "process_creation",
    signature: set[tuple[str, str]] | None = None,
) -> RuleInfo:
    return RuleInfo(
        rule_id=rule_id,
        title=rule_id,
        path=f"{rule_id}.yml",
        product=product,
        category=category,
        technique_ids=frozenset(technique_ids),
        tactics=frozenset(),
        signature=frozenset(signature or {("Image", rule_id)}),
    )


# --------------------------------------------------------------------------- #
# rules: tag extraction + loading
# --------------------------------------------------------------------------- #
def test_extract_attack_tags_from_loaded_rule(tmp_path: Path) -> None:
    rule_file = tmp_path / "rules" / "whoami.yml"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text(_RULE_YAML, encoding="utf-8")

    infos = load_rules(tmp_path / "rules")
    assert len(infos) == 1
    info = infos[0]
    assert info.technique_ids == frozenset({"T1033"})
    assert info.tactics == frozenset({"discovery"})
    assert info.product == "windows"
    assert info.category == "process_creation"
    # The endswith modifier expands into a (field, value) signature pair.
    assert any(field == "Image" for field, _ in info.signature)


def test_extract_attack_tags_uppercases_techniques() -> None:
    from sigma.collection import SigmaCollection

    rule = SigmaCollection.from_yaml(_RULE_YAML).rules[0]
    techniques, tactics = extract_attack_tags(rule)
    assert techniques == frozenset({"T1033"})
    assert tactics == frozenset({"discovery"})


def test_load_rules_skips_invalid_files(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "good.yml").write_text(_RULE_YAML, encoding="utf-8")
    (rules_dir / "bad.yml").write_text("not: a: valid: sigma: rule:\n  - [", encoding="utf-8")
    infos = load_rules(rules_dir)
    assert [info.technique_ids for info in infos] == [frozenset({"T1033"})]


# --------------------------------------------------------------------------- #
# matrix
# --------------------------------------------------------------------------- #
def test_build_coverage_matrix_counts_and_percentage() -> None:
    rules = [_rule("r1", {"T1033"}), _rule("r2", set())]
    matrix = build_coverage_matrix(rules, _catalog())

    assert matrix.total_techniques == 4
    assert matrix.covered_techniques == 1
    assert matrix.coverage_pct == 25.0
    assert matrix.techniques[0].technique_id == "T1033"
    assert matrix.techniques[0].name == "System Owner/User Discovery"
    assert matrix.techniques[0].rule_count == 1
    assert matrix.untagged_rules == ["r2"]


def test_build_coverage_matrix_aggregates_multiple_rules() -> None:
    rules = [_rule("r1", {"T1033"}), _rule("r2", {"T1033"})]
    matrix = build_coverage_matrix(rules, _catalog())
    assert matrix.covered_techniques == 1
    assert matrix.techniques[0].rule_count == 2
    assert matrix.techniques[0].rule_ids == ["r1", "r2"]


# --------------------------------------------------------------------------- #
# navigator
# --------------------------------------------------------------------------- #
def test_build_navigator_layer_shape() -> None:
    matrix = build_coverage_matrix([_rule("r1", {"T1033"})], _catalog())
    layer = build_navigator_layer(matrix, attack_version="15")

    assert layer["versions"] == {"navigator": "5.2.0", "layer": "4.5", "attack": "15"}
    assert layer["domain"] == "enterprise-attack"
    techniques = layer["techniques"]
    assert isinstance(techniques, list)
    assert techniques[0]["techniqueID"] == "T1033"
    assert techniques[0]["score"] == 1
    assert techniques[0]["enabled"] is True
    gradient = layer["gradient"]
    assert isinstance(gradient, dict)
    assert len(gradient["colors"]) >= 2
    assert gradient["minValue"] == 0
    assert gradient["maxValue"] >= 1


def test_navigator_layer_omits_attack_version_when_blank() -> None:
    matrix = build_coverage_matrix([_rule("r1", {"T1033"})], _catalog())
    layer = build_navigator_layer(matrix)
    assert "attack" not in layer["versions"]  # type: ignore[operator]


# --------------------------------------------------------------------------- #
# gaps
# --------------------------------------------------------------------------- #
def test_identify_gaps_prioritises_high_value_tactics() -> None:
    report = identify_gaps(["T1033"], _catalog())
    by_id = {gap.technique_id: gap for gap in report.gaps}

    # T1033 is covered -> not a gap.
    assert "T1033" not in by_id
    # Parent technique in a high-value tactic -> high priority.
    assert by_id["T1003"].priority == "high"
    # Sub-technique in a high-value tactic -> demoted to medium, names its parent.
    assert by_id["T1003.001"].priority == "medium"
    assert any("T1003" in reason for reason in by_id["T1003.001"].reasons)
    # Sub-technique in a low-value tactic -> low priority.
    assert by_id["T1595.001"].priority == "low"


def test_identify_gaps_orders_high_priority_first() -> None:
    report = identify_gaps([], _catalog())
    priorities = [gap.priority for gap in report.gaps]
    assert priorities == sorted(priorities, key=lambda p: {"high": 0, "medium": 1, "low": 2}[p])


def test_identify_gaps_scopes_by_platform() -> None:
    report = identify_gaps([], _catalog(), platforms=["Windows"])
    ids = {gap.technique_id for gap in report.gaps}
    assert "T1595.001" not in ids  # PRE-only technique is filtered out
    assert "T1003" in ids
    assert report.scope["platforms"] == ["windows"]


# --------------------------------------------------------------------------- #
# overlap
# --------------------------------------------------------------------------- #
def test_find_overlaps_flags_shared_technique_and_similar_logic() -> None:
    shared_sig = {("Image", "same")}
    rules = [
        _rule("a", {"T1033"}, signature=shared_sig),
        _rule("b", {"T1033"}, signature={("CommandLine", "x")}),
        _rule("c", {"T1059"}, product="linux", signature=shared_sig),
        _rule("d", {"T9999"}, signature=shared_sig),
    ]
    report = find_overlaps(rules, min_similarity=0.6)
    pair_titles = {frozenset((p.rule_a, p.rule_b)) for p in report.pairs}

    # a & b share technique T1033.
    assert frozenset({"a", "b"}) in pair_titles
    # a & d have identical signatures within the same log source.
    assert frozenset({"a", "d"}) in pair_titles
    ad = next(p for p in report.pairs if frozenset((p.rule_a, p.rule_b)) == frozenset({"a", "d"}))
    assert ad.field_similarity == 1.0
    # a & c share a signature but differ in log source -> not flagged.
    assert frozenset({"a", "c"}) not in pair_titles


# --------------------------------------------------------------------------- #
# baseline (fake backend)
# --------------------------------------------------------------------------- #
class _FakeBackend:
    siem_id = "fake"

    def __init__(self, results: dict[str, FieldAggregation]) -> None:
        self._results = results

    def aggregate_field(
        self,
        field: str,
        *,
        index: str | None = None,
        lookback_days: int = 7,
        top_n: int = 10,
    ) -> FieldAggregation:
        return self._results[field]


def test_profile_fields_flags_high_cardinality_as_noisy() -> None:
    results = {
        "user.name": FieldAggregation(
            backend="fake", field="user.name", total_events=1000, distinct_values=900
        ),
        "event.code": FieldAggregation(
            backend="fake", field="event.code", total_events=1000, distinct_values=3
        ),
        "empty": FieldAggregation(backend="fake", field="empty", total_events=0),
    }
    report = profile_fields(_FakeBackend(results), ["user.name", "event.code", "empty"])
    by_field = {fb.field: fb for fb in report.fields}

    assert report.siem == "fake"
    assert by_field["user.name"].noisy is True
    assert by_field["event.code"].noisy is False
    assert by_field["empty"].noisy is False
    assert "no events" in by_field["empty"].note


# --------------------------------------------------------------------------- #
# SIEM aggregation helpers (pure)
# --------------------------------------------------------------------------- #
def test_build_terms_aggregation_structure() -> None:
    agg = build_terms_aggregation("user.name", 5)
    assert agg["top"]["terms"] == {"field": "user.name", "size": 5}
    assert agg["distinct"]["cardinality"] == {"field": "user.name"}


def test_parse_terms_aggregation_maps_response() -> None:
    resp = {
        "hits": {"total": {"value": 1000}},
        "aggregations": {
            "top": {"buckets": [{"key": "alice", "doc_count": 7}, {"key": "bob", "doc_count": 3}]},
            "distinct": {"value": 42},
        },
    }
    result = parse_terms_aggregation(resp, backend="elk", field="user.name", index="logs-*")
    assert result.total_events == 1000
    assert result.distinct_values == 42
    assert result.top_values == [
        {"value": "alice", "count": 7},
        {"value": "bob", "count": 3},
    ]


# --------------------------------------------------------------------------- #
# DeTT&CT (disabled / unavailable paths)
# --------------------------------------------------------------------------- #
def test_dettect_disabled_is_not_available() -> None:
    settings = CoverageSettings(dettect_enabled=False)
    assert is_available(settings) is False
    result = generate_layer(settings, "ds", "whatever.yaml")
    assert result.available is False
    assert "disabled" in result.message


def test_dettect_unknown_mode_is_rejected() -> None:
    settings = CoverageSettings(dettect_enabled=True, dettect_command="")
    result = generate_layer(settings, "bogus", "whatever.yaml")
    assert result.available is True
    assert "unknown DeTT&CT mode" in result.message


def test_dettect_resolves_script_path(tmp_path: Path) -> None:
    script = tmp_path / "DeTTECT" / "dettect.py"
    script.parent.mkdir(parents=True)
    script.write_text("# stub\n", encoding="utf-8")
    resolved = _resolve_command(CoverageSettings(dettect_enabled=True, dettect_command=str(script)))
    assert resolved is not None
    argv, cwd = resolved
    assert argv[-1] == str(script)
    assert cwd == script.parent
