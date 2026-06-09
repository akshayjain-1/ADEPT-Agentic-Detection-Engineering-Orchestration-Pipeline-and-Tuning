"""Build the ATT&CK coverage matrix from local rules and an ATT&CK catalogue."""

from __future__ import annotations

from collections.abc import Iterable

from adept.coverage.attack_data import CatalogProtocol
from adept.coverage.models import CoverageMatrix, TechniqueCoverage
from adept.coverage.rules import RuleInfo, rules_to_techniques


def build_coverage_matrix(rules: Iterable[RuleInfo], catalog: CatalogProtocol) -> CoverageMatrix:
    """Compute technique coverage of ``rules`` against the ATT&CK ``catalog``."""
    rule_list = list(rules)
    mapping = rules_to_techniques(rule_list)
    catalog_ids = {meta.technique_id for meta in catalog.techniques()}

    coverages: list[TechniqueCoverage] = []
    for technique_id, covering in mapping.items():
        meta_name = catalog.name(technique_id)
        tactics = sorted({tactic for rule in covering for tactic in rule.tactics})
        coverages.append(
            TechniqueCoverage(
                technique_id=technique_id,
                name=meta_name or technique_id,
                tactics=tactics,
                rule_count=len(covering),
                rule_ids=sorted(rule.rule_id for rule in covering),
                rule_titles=sorted(rule.title for rule in covering),
            )
        )

    coverages.sort(key=lambda cov: (-cov.rule_count, cov.technique_id))
    untagged = sorted({rule.title for rule in rule_list if not rule.technique_ids})

    total = len(catalog_ids)
    covered = len(set(mapping) & catalog_ids)
    pct = round(100.0 * covered / total, 2) if total else 0.0

    return CoverageMatrix(
        total_techniques=total,
        covered_techniques=covered,
        coverage_pct=pct,
        techniques=coverages,
        untagged_rules=untagged,
    )
