"""TP/FP sample-event unit tests for Sigma rules.

A test file (``sigma_rules/tests/<stem>.yml``) names a rule and lists
``true_positives`` (events that must match) and ``false_positives`` (events
that must not). This harness loads the rule, evaluates each sample event with
:func:`adept.detection_as_code.matcher.evaluate_rule`, and reports pass/fail.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from adept.detection_as_code.matcher import evaluate_rule
from adept.detection_as_code.models import UnitTestCaseResult, UnitTestReport
from adept.shared.errors import ConfigurationError, ValidationFailedError


def _load_rule(rule_path: Path) -> Any:
    try:
        collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    except (SigmaError, yaml.YAMLError) as exc:
        raise ValidationFailedError(f"{rule_path}: failed to parse: {exc}") from exc
    if not collection.rules:
        raise ValidationFailedError(f"{rule_path}: no rule found")
    return collection.rules[0]


def _cases(
    samples: list[dict[str, Any]],
    kind: Literal["true_positive", "false_positive"],
    expected_match: bool,
    rule: Any,
) -> list[UnitTestCaseResult]:
    results: list[UnitTestCaseResult] = []
    for index, sample in enumerate(samples):
        name = str(sample.get("name", f"{kind}[{index}]"))
        event = sample.get("event", {})
        if not isinstance(event, dict):
            raise ValidationFailedError(f"sample {name!r}: 'event' must be a mapping")
        actual = evaluate_rule(rule, event)
        results.append(
            UnitTestCaseResult(
                name=name,
                kind=kind,
                expected_match=expected_match,
                actual_match=actual,
                passed=actual == expected_match,
            )
        )
    return results


def run_test_file(test_path: Path, repo_root: Path | None = None) -> UnitTestReport:
    """Run the TP/FP unit tests defined in ``test_path``.

    ``repo_root`` defaults to the test file's grandparent (``tests/`` lives at
    the repository root), which is where the referenced ``rule:`` path is
    resolved from.
    """
    spec = yaml.safe_load(test_path.read_text(encoding="utf-8"))
    if not isinstance(spec, dict) or "rule" not in spec:
        raise ConfigurationError(f"{test_path}: test file must define a 'rule' path")

    root = repo_root if repo_root is not None else test_path.resolve().parents[1]
    rule_path = (root / str(spec["rule"])).resolve()
    if not rule_path.is_file():
        raise ConfigurationError(f"{test_path}: referenced rule {rule_path} not found")

    rule = _load_rule(rule_path)
    cases = _cases(spec.get("true_positives", []) or [], "true_positive", True, rule)
    cases += _cases(spec.get("false_positives", []) or [], "false_positive", False, rule)

    passed = sum(1 for case in cases if case.passed)
    return UnitTestReport(
        rule=str(spec["rule"]),
        rule_id=str(getattr(rule, "id", "")),
        ok=passed == len(cases),
        total=len(cases),
        passed=passed,
        failed=len(cases) - passed,
        cases=cases,
    )
