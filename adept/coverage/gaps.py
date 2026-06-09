"""Prioritise uncovered ATT&CK techniques (detection gaps).

Gaps are the techniques in the (optionally platform/tactic-scoped) ATT&CK
universe that no local rule covers. Prioritisation is a documented heuristic:
techniques in high-signal kill-chain tactics rank highest, parent techniques
rank above sub-techniques, and the scope filters keep the list relevant to the
environment.
"""

from __future__ import annotations

from collections.abc import Iterable

from adept.coverage.attack_data import CatalogProtocol, TechniqueMeta
from adept.coverage.models import CoverageGap, GapReport, Priority

# Tactics most associated with high-value, detectable adversary behaviour.
DEFAULT_HIGH_VALUE_TACTICS: frozenset[str] = frozenset(
    {
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "lateral-movement",
        "command-and-control",
    }
)
_PRIORITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _normalise(values: Iterable[str] | None) -> set[str]:
    return {value.strip().lower() for value in values} if values else set()


def _in_scope(meta: TechniqueMeta, platforms: set[str], tactics: set[str]) -> bool:
    if platforms and not ({p.lower() for p in meta.platforms} & platforms):
        return False
    if tactics and not (set(meta.tactics) & tactics):
        return False
    return True


def _prioritise(meta: TechniqueMeta, high_value: set[str]) -> tuple[Priority, list[str]]:
    reasons: list[str] = []
    high_tactics = sorted(set(meta.tactics) & high_value)
    if high_tactics:
        reasons.append("high-signal tactic(s): " + ", ".join(high_tactics))

    priority: Priority
    if meta.is_subtechnique:
        priority = "medium" if high_tactics else "low"
        parent = meta.technique_id.split(".")[0]
        reasons.append(f"sub-technique — consider covering parent {parent} first")
    else:
        priority = "high" if high_tactics else "medium"
    return priority, reasons


def identify_gaps(
    covered_technique_ids: Iterable[str],
    catalog: CatalogProtocol,
    *,
    platforms: Iterable[str] | None = None,
    tactics: Iterable[str] | None = None,
    high_value_tactics: Iterable[str] | None = None,
) -> GapReport:
    """Return prioritised ATT&CK techniques with no local coverage."""
    covered = {tid.upper() for tid in covered_technique_ids}
    platform_filter = _normalise(platforms)
    tactic_filter = _normalise(tactics)
    high_value = _normalise(high_value_tactics) or set(DEFAULT_HIGH_VALUE_TACTICS)

    in_scope = [
        meta for meta in catalog.techniques() if _in_scope(meta, platform_filter, tactic_filter)
    ]

    gaps: list[CoverageGap] = []
    for meta in in_scope:
        if meta.technique_id in covered:
            continue
        priority, reasons = _prioritise(meta, high_value)
        if platform_filter:
            reasons.append("platform match: " + ", ".join(sorted(meta.platforms)))
        gaps.append(
            CoverageGap(
                technique_id=meta.technique_id,
                name=meta.name,
                tactics=list(meta.tactics),
                platforms=list(meta.platforms),
                priority=priority,
                reasons=reasons,
            )
        )

    gaps.sort(key=lambda gap: (_PRIORITY_RANK[gap.priority], gap.technique_id))
    covered_in_scope = len({meta.technique_id for meta in in_scope} & covered)
    return GapReport(
        scope={"platforms": sorted(platform_filter), "tactics": sorted(tactic_filter)},
        total_in_scope=len(in_scope),
        covered_in_scope=covered_in_scope,
        total_gaps=len(gaps),
        gaps=gaps,
    )
