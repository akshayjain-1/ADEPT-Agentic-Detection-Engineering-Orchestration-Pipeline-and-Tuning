"""Evaluate a Sigma rule's detection logic against a sample event.

pySigma has no built-in event-matching engine, so this module walks the parsed
condition AST (verified shapes: ``ConditionAND/OR/NOT``,
``ConditionFieldEqualsValueExpression``, ``ConditionValueExpression``) and the
already-expanded value types (``SigmaString`` with baked-in wildcards,
``SigmaNumber``, ``SigmaRegularExpression``, ``SigmaNull``, ``SigmaBool``).

Field modifiers such as ``contains``/``startswith``/``endswith`` are *already*
expanded into wildcard ``SigmaString`` values by the parser, so they need no
special handling here. Anything genuinely unsupported raises
``ValidationFailedError`` rather than silently returning a wrong verdict — a
silent mismatch in a detection test would be worse than a loud failure.

Matching semantics follow the Sigma specification: a ``field: value`` plain
string must equal the whole field value (case-insensitive); wildcards widen
that. A value-only *keyword* matches as a substring of any field value.
"""

from __future__ import annotations

import re
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from adept.shared.errors import ValidationFailedError

Event = dict[str, Any]


def _regex_body(value: SigmaString) -> str:
    """Translate a SigmaString's parts into a regex fragment (no anchors)."""
    parts: list[str] = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(str(part)))
    return "".join(parts)


def _field_pattern(value: SigmaString) -> re.Pattern[str]:
    return re.compile("^" + _regex_body(value) + "$", re.IGNORECASE | re.DOTALL)


def _keyword_pattern(value: SigmaString) -> re.Pattern[str]:
    return re.compile(_regex_body(value), re.IGNORECASE | re.DOTALL)


def _as_iter(field_value: Any) -> list[Any]:
    if isinstance(field_value, (list, tuple, set)):
        return list(field_value)
    return [field_value]


def _match_string(value: SigmaString, field_value: Any) -> bool:
    pattern = _field_pattern(value)
    return any(
        item is not None and pattern.match(str(item)) is not None for item in _as_iter(field_value)
    )


def _match_number(value: SigmaNumber, field_value: Any) -> bool:
    for item in _as_iter(field_value):
        try:
            if item is not None and float(item) == float(value.number):
                return True
        except (TypeError, ValueError):
            continue
    return False


_RE_FLAG_BY_NAME: dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


def _regex_flags(value: SigmaRegularExpression) -> int:
    """Translate a SigmaRegularExpression's flags into Python ``re`` flags.

    pySigma carries regex modifiers (``i``/``m``/``s``) as a set of flag enum
    members; mapping them by name keeps the offline backtest matcher in step with
    the deployed SIEM query and is robust across pySigma versions.
    """
    combined = 0
    for flag in getattr(value, "flags", None) or ():
        combined |= _RE_FLAG_BY_NAME.get(getattr(flag, "name", ""), 0)
    return combined


def _match_regex(value: SigmaRegularExpression, field_value: Any) -> bool:
    pattern = re.compile(str(value.regexp), _regex_flags(value))
    return any(
        item is not None and pattern.search(str(item)) is not None for item in _as_iter(field_value)
    )


def _match_value(value: Any, field_value: Any, present: bool) -> bool:
    if isinstance(value, SigmaNull):
        return not present or all(item is None for item in _as_iter(field_value))
    if not present:
        return False
    if isinstance(value, SigmaString):
        return _match_string(value, field_value)
    if isinstance(value, SigmaNumber):
        return _match_number(value, field_value)
    if isinstance(value, SigmaBool):
        return any(bool(item) == value.boolean for item in _as_iter(field_value))
    if isinstance(value, SigmaRegularExpression):
        return _match_regex(value, field_value)
    raise ValidationFailedError(
        f"unsupported Sigma value type in detection test: {type(value).__name__}"
    )


def _match_keyword(value: Any, event: Event) -> bool:
    """A value-only (keyword) expression matches as a substring of any value."""
    if not isinstance(value, SigmaString):
        raise ValidationFailedError(
            f"unsupported keyword value type in detection test: {type(value).__name__}"
        )
    pattern = _keyword_pattern(value)
    for field_value in event.values():
        if any(
            item is not None and pattern.search(str(item)) is not None
            for item in _as_iter(field_value)
        ):
            return True
    return False


def _eval(node: Any, event: Event) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        present = node.field in event
        return _match_value(node.value, event.get(node.field), present)
    if isinstance(node, ConditionValueExpression):
        return _match_keyword(node.value, event)
    raise ValidationFailedError(
        f"unsupported condition node in detection test: {type(node).__name__}"
    )


def evaluate_rule(rule: SigmaRule, event: Event) -> bool:
    """Return ``True`` if ``event`` matches ``rule``'s detection logic.

    Multiple ``condition`` entries are treated as a logical OR (a rule fires if
    any of its conditions match), matching Sigma semantics.
    """
    conditions = rule.detection.parsed_condition
    if not conditions:
        raise ValidationFailedError("rule has no parsed condition to evaluate")
    return any(_eval(condition.parsed, event) for condition in conditions)
