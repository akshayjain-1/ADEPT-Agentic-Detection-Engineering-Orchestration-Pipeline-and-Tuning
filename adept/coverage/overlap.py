"""Detect overlapping or duplicate rules in the local ruleset.

Two signals are combined: rules that map to the same ATT&CK technique, and rules
with similar detection logic (Jaccard similarity of their ``(field, value)``
signatures, compared only within the same log source). The result is a list of
candidate pairs for an author to review before adding yet another rule.
"""

from __future__ import annotations

from collections.abc import Iterable
from itertools import combinations

from adept.coverage.models import OverlapPair, OverlapReport
from adept.coverage.rules import RuleInfo


def _jaccard(a: frozenset[tuple[str, str]], b: frozenset[tuple[str, str]]) -> float:
    if not a or not b:
        return 0.0
    union = len(a | b)
    return round(len(a & b) / union, 3) if union else 0.0


def _same_logsource(a: RuleInfo, b: RuleInfo) -> bool:
    return (a.product, a.category, a.service) == (b.product, b.category, b.service)


def find_overlaps(rules: Iterable[RuleInfo], *, min_similarity: float = 0.6) -> OverlapReport:
    """Return candidate overlapping/duplicate rule pairs."""
    rule_list = list(rules)
    pairs: list[OverlapPair] = []

    for left, right in combinations(rule_list, 2):
        shared = sorted(left.technique_ids & right.technique_ids)
        similarity = (
            _jaccard(left.signature, right.signature) if _same_logsource(left, right) else 0.0
        )

        reasons: list[str] = []
        if shared:
            reasons.append("shared ATT&CK technique(s): " + ", ".join(shared))
        if similarity >= min_similarity:
            reasons.append(f"similar detection logic (Jaccard {similarity})")
        if not reasons:
            continue

        pairs.append(
            OverlapPair(
                rule_a=left.title,
                rule_b=right.title,
                shared_techniques=shared,
                field_similarity=similarity,
                reasons=reasons,
            )
        )

    pairs.sort(key=lambda pair: (-len(pair.shared_techniques), -pair.field_similarity))
    return OverlapReport(total=len(pairs), pairs=pairs)
