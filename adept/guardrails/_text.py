"""Shared text helpers for the deterministic query linters."""

from __future__ import annotations

import re

from adept.guardrails.models import LintFinding, finding

#: Matches a double-quoted string (honouring backslash escapes) so quoted
#: content can be blanked out before structural scanning.
QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def blank_quotes(text: str) -> str:
    """Replace the contents of double-quoted strings with empty quotes."""
    return QUOTED.sub('""', text)


def balance_findings(text: str, artifact: str) -> list[LintFinding]:
    """Report unbalanced quotes, parentheses, and brackets in ``text``."""
    findings: list[LintFinding] = []
    if text.count('"') % 2 != 0:
        findings.append(
            finding(f"{artifact}.unbalanced_quotes", "error", "Unbalanced double quotes.")
        )
    blanked = blank_quotes(text)
    for open_char, close_char, label in (("(", ")", "parentheses"), ("[", "]", "brackets")):
        if blanked.count(open_char) != blanked.count(close_char):
            findings.append(
                finding(f"{artifact}.unbalanced_{label}", "error", f"Unbalanced {label}.")
            )
    return findings
