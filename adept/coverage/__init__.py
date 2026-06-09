"""ATT&CK coverage analysis for ADEPT.

Builds a technique coverage matrix from the local Sigma ruleset, exports ATT&CK
Navigator layers, prioritises detection gaps, finds overlapping/duplicate rules,
profiles SIEM field baselines for noise estimation, and optionally bridges to
DeTT&CT (external, best-effort) for data-source/visibility layers.
"""

from __future__ import annotations

from adept.coverage.attack_data import AttackCatalog, CatalogProtocol, TechniqueMeta
from adept.coverage.baseline import AggregatingBackend, profile_fields
from adept.coverage.dettect import DettectResult, generate_layer, is_available
from adept.coverage.gaps import DEFAULT_HIGH_VALUE_TACTICS, identify_gaps
from adept.coverage.matrix import build_coverage_matrix
from adept.coverage.models import (
    BaselineReport,
    CoverageGap,
    CoverageMatrix,
    FieldBaseline,
    GapReport,
    OverlapPair,
    OverlapReport,
    Priority,
    TechniqueCoverage,
)
from adept.coverage.navigator import (
    LAYER_VERSION,
    NAVIGATOR_VERSION,
    build_navigator_layer,
)
from adept.coverage.overlap import find_overlaps
from adept.coverage.rules import RuleInfo, extract_attack_tags, load_rules, rules_to_techniques

__all__ = [
    "DEFAULT_HIGH_VALUE_TACTICS",
    "LAYER_VERSION",
    "NAVIGATOR_VERSION",
    "AggregatingBackend",
    "AttackCatalog",
    "BaselineReport",
    "CatalogProtocol",
    "CoverageGap",
    "CoverageMatrix",
    "DettectResult",
    "FieldBaseline",
    "GapReport",
    "OverlapPair",
    "OverlapReport",
    "Priority",
    "RuleInfo",
    "TechniqueCoverage",
    "TechniqueMeta",
    "build_coverage_matrix",
    "build_navigator_layer",
    "extract_attack_tags",
    "find_overlaps",
    "generate_layer",
    "identify_gaps",
    "is_available",
    "load_rules",
    "profile_fields",
    "rules_to_techniques",
]
