"""Deterministic, offline safety linter for Splunk SPL.

Detection searches must never write, execute, or exfiltrate data. This offline
check (no live Splunk needed) refuses SPL that pipes into a side-effecting
command and flags obvious syntax breakage, so an LLM-authored search cannot,
for example, ``| delete`` events or ``| sendemail`` results.

**Scope — this is best-effort defense-in-depth, not the primary control.** The
real safety boundary is the human approval gate (every state-changing tool is
gated) plus least-privilege SIEM credentials; this linter is a fast and
deterministic backstop that catches the obvious cases first. Because it matches
on the *leading command name* of each pipe segment (after blanking quoted text),
it deliberately trades completeness for a near-zero false-positive rate:

* Dangerous commands are caught even inside a subsearch, because the segmenter
  splits on every ``|`` regardless of bracket nesting.
* Commands whose danger depends on their *arguments* rather than their name are
  **not** blocked by default, to avoid rejecting legitimate detections — e.g.
  ``rest`` (read-only by default but able to POST/DELETE to the management API)
  or ``map`` (chains a search per row). Operators who want them refused can add
  them via ``ADEPT_AGENT__SPL_DENYLIST``.
"""

from __future__ import annotations

import re
from collections.abc import Collection

from adept.guardrails._text import balance_findings, blank_quotes
from adept.guardrails.models import LintFinding, LintReport, finding

#: SPL commands that write to disk/index, send data out, or run code. None of
#: these belong in a read-only detection search.
DANGEROUS_SPL_COMMANDS: frozenset[str] = frozenset(
    {
        "delete",
        "outputlookup",
        "outputcsv",
        "sendemail",
        "sendalert",
        "script",
        "runshell",
        "collect",
        "summaryindex",
        "stash",
        "tscollect",
        "mcollect",
        "meventcollect",
        "crawl",
        "dump",
        "external",
        "extern",
    }
)

#: Leading identifier of an SPL command segment (after a pipe), tolerating a
#: leading subsearch ``[`` or a macro backtick.
_LEADING_IDENT = re.compile(r"^\s*\[?\s*`?\s*([A-Za-z_][\w]*)")


def lint_spl(query: str, *, denylist: Collection[str] | None = None) -> LintReport:
    """Lint an SPL query for forbidden commands and basic syntax breakage."""
    commands = frozenset(
        item.lower() for item in (DANGEROUS_SPL_COMMANDS if denylist is None else denylist)
    )
    stripped = query.strip()
    if not stripped:
        return LintReport(
            artifact="spl", findings=[finding("spl.empty", "error", "SPL query is empty.")]
        )

    findings: list[LintFinding] = list(balance_findings(stripped, "spl"))
    # The first segment is the base search; every segment after a pipe is a command.
    segments = blank_quotes(stripped).split("|")
    for segment in segments[1:]:
        match = _LEADING_IDENT.match(segment)
        if match is None:
            if not segment.strip():
                findings.append(finding("spl.empty_pipe", "error", "Empty command after '|'."))
            continue
        name = match.group(1).lower()
        if name in commands:
            findings.append(
                finding(
                    "spl.forbidden_command",
                    "error",
                    f"SPL command '{name}' is not allowed in a detection search; "
                    "it writes, executes, or exfiltrates data.",
                )
            )
    return LintReport(artifact="spl", findings=findings)
