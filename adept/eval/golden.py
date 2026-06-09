"""Offline component evaluation: score golden detection cases with the matcher.

Each :class:`GoldenCase` pairs a Sigma rule with positive events (which must
fire it) and negative events (which must not). The real
:func:`adept.detection_as_code.matcher.evaluate_rule` decides each verdict, so
this is a deterministic, LLM-free regression of detection quality that runs in
CI. A case "passes" only when it catches every positive and raises no false
positive.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from adept.detection_as_code.matcher import evaluate_rule
from adept.eval.models import EvalCaseResult, EvalReport, GoldenCase
from adept.shared.errors import ValidationFailedError


def _load_rule(rule_text: str) -> Any:
    try:
        collection = SigmaCollection.from_yaml(rule_text)
    except (SigmaError, yaml.YAMLError) as exc:
        raise ValidationFailedError(f"failed to parse golden rule: {exc}") from exc
    if not collection.rules:
        raise ValidationFailedError("golden rule defined no rule")
    return collection.rules[0]


def _f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return round(2 * precision * recall / (precision + recall), 4)


def _ratio(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else round(numerator / denominator, 4)


def evaluate_case(case: GoldenCase) -> EvalCaseResult:
    """Evaluate one golden case into a confusion matrix and scores."""
    rule = _load_rule(case.rule)
    tp = sum(1 for event in case.positives if evaluate_rule(rule, event))
    fn = len(case.positives) - tp
    fp = sum(1 for event in case.negatives if evaluate_rule(rule, event))
    tn = len(case.negatives) - fp
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return EvalCaseResult(
        name=case.name,
        technique=case.technique,
        rule_id=str(getattr(rule, "id", "") or ""),
        true_positives=tp,
        false_negatives=fn,
        true_negatives=tn,
        false_positives=fp,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
        passed=fn == 0 and fp == 0,
    )


def run_component_eval(cases: Sequence[GoldenCase]) -> EvalReport:
    """Evaluate every golden case and aggregate a micro-averaged report."""
    results = [evaluate_case(case) for case in cases]
    tp = sum(r.true_positives for r in results)
    fn = sum(r.false_negatives for r in results)
    tn = sum(r.true_negatives for r in results)
    fp = sum(r.false_positives for r in results)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return EvalReport(
        total_cases=len(results),
        passed_cases=sum(1 for r in results if r.passed),
        true_positives=tp,
        false_negatives=fn,
        true_negatives=tn,
        false_positives=fp,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
        cases=results,
    )


def _windows_process(image: str, command_line: str) -> dict[str, Any]:
    return {"Image": image, "CommandLine": command_line}


# A small, deterministic golden set covering common ATT&CK techniques. These are
# illustrative regression anchors, not a complete detection library.
DEFAULT_CASES: tuple[GoldenCase, ...] = (
    GoldenCase(
        name="PowerShell encoded command",
        technique="T1059.001",
        rule="""
title: PowerShell Encoded Command
id: 7b2f0c1a-1d3e-4a5b-8c6d-0e1f2a3b4c5d
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
""",
        positives=[
            _windows_process(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe -enc ZQBjAGgAbwA=",
            ),
        ],
        negatives=[
            _windows_process(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe Get-Process",
            ),
            _windows_process("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami"),
        ],
    ),
    GoldenCase(
        name="LSASS memory access",
        technique="T1003.001",
        rule="""
title: LSASS Memory Access
id: 1c9d8e7f-6a5b-4c3d-2e1f-0a9b8c7d6e5f
status: test
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess: '0x1410'
  condition: selection
""",
        positives=[
            {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1410"},
        ],
        negatives=[
            {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1000"},
            {"TargetImage": "C:\\Windows\\System32\\svchost.exe", "GrantedAccess": "0x1410"},
        ],
    ),
    GoldenCase(
        name="Registry Run key persistence",
        technique="T1547.001",
        rule="""
title: Registry Run Key Persistence
id: 9f8e7d6c-5b4a-4938-2716-0a1b2c3d4e5f
status: test
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains: '\\CurrentVersion\\Run'
  condition: selection
""",
        positives=[
            {"TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil"},
        ],
        negatives=[
            {
                "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
            },
        ],
    ),
)
