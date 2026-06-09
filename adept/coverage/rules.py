"""Extract ATT&CK tags and detection signatures from local Sigma rules.

:class:`RuleInfo` is the analysis-friendly projection of a Sigma rule: its
identity, log source, the ATT&CK techniques/tactics it is tagged with, and a
coarse ``(field, value)`` signature used for overlap detection.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.exceptions import SigmaError

from adept.shared.logging import get_logger

log = get_logger(__name__)

_TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$")


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """Analysis projection of a single Sigma rule."""

    rule_id: str
    title: str
    path: str
    product: str = ""
    category: str = ""
    service: str = ""
    technique_ids: frozenset[str] = frozenset()
    tactics: frozenset[str] = frozenset()
    signature: frozenset[tuple[str, str]] = frozenset()


def extract_attack_tags(rule: Any) -> tuple[frozenset[str], frozenset[str]]:
    """Return ``(technique_ids, tactic_shortnames)`` from a rule's ATT&CK tags."""
    techniques: set[str] = set()
    tactics: set[str] = set()
    for tag in getattr(rule, "tags", []):
        if getattr(tag, "namespace", "") != "attack":
            continue
        name = str(getattr(tag, "name", ""))
        if _TECHNIQUE_RE.match(name):
            techniques.add(name.upper())
        elif name:
            tactics.add(name)
    return frozenset(techniques), frozenset(tactics)


def _iter_field_equals(node: Any) -> Iterator[tuple[str, str]]:
    """Yield ``(field, value)`` pairs from a parsed Sigma condition AST."""
    if isinstance(node, ConditionFieldEqualsValueExpression):
        yield str(node.field), str(node.value)
    elif isinstance(node, ConditionAND | ConditionOR | ConditionNOT):
        for arg in node.args:
            yield from _iter_field_equals(arg)


def _signature(rule: Any) -> frozenset[tuple[str, str]]:
    detection = getattr(rule, "detection", None)
    parsed_conditions = getattr(detection, "parsed_condition", None)
    if not parsed_conditions:
        return frozenset()
    pairs: set[tuple[str, str]] = set()
    try:
        for condition in parsed_conditions:
            pairs.update(_iter_field_equals(condition.parsed))
    except SigmaError:  # pragma: no cover - defensive; keep loading other rules
        return frozenset()
    return frozenset(pairs)


def _rule_info(rule: Any, path: Path) -> RuleInfo:
    techniques, tactics = extract_attack_tags(rule)
    logsource = getattr(rule, "logsource", None)
    rule_id = getattr(rule, "id", None)
    return RuleInfo(
        rule_id=str(rule_id) if rule_id else path.stem,
        title=str(getattr(rule, "title", "") or path.stem),
        path=str(path),
        product=str(getattr(logsource, "product", "") or ""),
        category=str(getattr(logsource, "category", "") or ""),
        service=str(getattr(logsource, "service", "") or ""),
        technique_ids=techniques,
        tactics=tactics,
        signature=_signature(rule),
    )


def load_rules(rules_dir: Path) -> list[RuleInfo]:
    """Load every Sigma rule under ``rules_dir`` into :class:`RuleInfo` objects."""
    rules_dir = Path(rules_dir)
    infos: list[RuleInfo] = []
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        except (SigmaError, OSError, ValueError, yaml.YAMLError) as exc:
            log.warning("coverage.rule_load_failed", path=str(path), error=str(exc))
            continue
        for rule in collection.rules:
            infos.append(_rule_info(rule, path))
    return infos


def rules_to_techniques(rules: Iterable[RuleInfo]) -> dict[str, list[RuleInfo]]:
    """Invert rules into ``technique_id -> [rules covering it]``."""
    mapping: dict[str, list[RuleInfo]] = {}
    for rule in rules:
        for technique_id in rule.technique_ids:
            mapping.setdefault(technique_id, []).append(rule)
    return mapping
