"""Deterministic, offline linter for Elasticsearch/OpenSearch Lucene queries."""

from __future__ import annotations

import re

from adept.guardrails._text import balance_findings, blank_quotes
from adept.guardrails.models import LintFinding, LintReport, finding

#: A wildcard ('*' or '?') at the start of a term. Rejected by the cluster
#: (``allow_leading_wildcard: false``) and forces a full-index scan.
_LEADING_WILDCARD = re.compile(r"(?:^|[\s:(])[*?]")


def lint_lucene(query: str) -> LintReport:
    """Lint a Lucene query for leading wildcards, match-all, and syntax breakage."""
    stripped = query.strip()
    if not stripped:
        return LintReport(
            artifact="lucene",
            findings=[finding("lucene.empty", "error", "Lucene query is empty.")],
        )
    findings: list[LintFinding] = list(balance_findings(stripped, "lucene"))
    blanked = blank_quotes(stripped)
    if blanked in {"*", "*:*"}:
        # The idiomatic match-all form: advisory (noisy/unbounded) rather than a
        # hard error, and handled here so it is not mistaken for a leading wildcard.
        findings.append(
            finding(
                "lucene.match_all",
                "warning",
                "Query matches all documents; add field constraints to avoid an unbounded scan.",
            )
        )
    elif _LEADING_WILDCARD.search(blanked):
        findings.append(
            finding(
                "lucene.leading_wildcard",
                "error",
                "A term begins with '*' or '?'; leading wildcards are rejected by the "
                "cluster and force a full scan. Anchor the term instead.",
            )
        )
    return LintReport(artifact="lucene", findings=findings)
