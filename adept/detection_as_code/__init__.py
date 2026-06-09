"""ADEPT detection-as-code: Sigma validation, conversion, and lifecycle."""

from __future__ import annotations

from adept.detection_as_code.backtest import backtest_rule
from adept.detection_as_code.converter import SigmaConverter
from adept.detection_as_code.lifecycle import (
    STAGE_TRANSITIONS,
    can_transition,
    load_metadata,
)
from adept.detection_as_code.matcher import evaluate_rule
from adept.detection_as_code.models import (
    BacktestResult,
    ConversionResult,
    UnitTestReport,
    ValidationIssue,
    ValidationReport,
)
from adept.detection_as_code.pipelines import build_pipeline, default_pipelines
from adept.detection_as_code.targets import (
    SIEM_CONVERTER_TARGETS,
    SIEM_IDS,
    SIEM_QUERY_LANGUAGE,
    converter_target,
)
from adept.detection_as_code.unit_tests import run_test_file
from adept.detection_as_code.validator import RuleValidator

__all__ = [
    "SIEM_CONVERTER_TARGETS",
    "SIEM_IDS",
    "SIEM_QUERY_LANGUAGE",
    "STAGE_TRANSITIONS",
    "BacktestResult",
    "ConversionResult",
    "RuleValidator",
    "SigmaConverter",
    "UnitTestReport",
    "ValidationIssue",
    "ValidationReport",
    "backtest_rule",
    "build_pipeline",
    "can_transition",
    "converter_target",
    "default_pipelines",
    "evaluate_rule",
    "load_metadata",
    "run_test_file",
]
