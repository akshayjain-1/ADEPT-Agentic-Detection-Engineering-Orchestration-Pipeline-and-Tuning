"""Deterministic linters for git branch names and commit messages."""

from __future__ import annotations

import re
from collections.abc import Collection

from adept.guardrails.models import LintFinding, LintReport, finding

#: Patterns git itself forbids in a ref name (a subset sufficient for vetting
#: agent-proposed branch names before they reach the repo).
_INVALID_BRANCH = re.compile(r"(\.\.|[ ~^:?*\[\\]|^[-/]|\.lock$|@\{|//)")


def lint_git_branch(branch: str, *, protected: Collection[str] = ()) -> LintReport:
    """Lint a target git branch: not protected, and a valid ref name."""
    name = branch.strip()
    if not name:
        return LintReport(
            artifact="git_branch",
            findings=[finding("git.empty_branch", "error", "Branch name is empty.")],
        )
    findings: list[LintFinding] = []
    if name in {item.strip() for item in protected}:
        findings.append(
            finding(
                "git.protected_branch",
                "error",
                f"'{name}' is a protected branch; author on a feature branch instead.",
            )
        )
    if _INVALID_BRANCH.search(name) or name.endswith("/"):
        findings.append(
            finding("git.invalid_branch", "error", f"'{name}' is not a valid git branch name.")
        )
    return LintReport(artifact="git_branch", findings=findings)


def lint_git_commit(message: str) -> LintReport:
    """Lint a git commit message: non-empty with a reasonable subject line."""
    text = message.strip()
    if not text:
        return LintReport(
            artifact="git_commit",
            findings=[finding("git.empty_commit", "error", "Commit message is empty.")],
        )
    findings: list[LintFinding] = []
    subject = text.splitlines()[0]
    if len(subject) > 72:
        findings.append(
            finding(
                "git.long_subject",
                "warning",
                "Commit subject exceeds 72 characters; keep the subject line concise.",
            )
        )
    return LintReport(artifact="git_commit", findings=findings)
