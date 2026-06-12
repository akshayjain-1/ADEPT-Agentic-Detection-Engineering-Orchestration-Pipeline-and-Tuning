"""Result models for ADEPT's deterministic output linters.

The guardrail linters return a :class:`LintReport` so the agent's evaluator
node and the per-tool lint middleware can make a uniform block/allow decision
across every artifact type (SPL, Lucene, Sigma, Navigator layers, git ops).
``error`` findings block; ``warning``/``info`` findings are advisory.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

#: ``error`` findings block (security/syntax); ``warning``/``info`` are advisory.
LintSeverity = Literal["error", "warning", "info"]


class LintFinding(BaseModel):
    """A single problem found in a generated artifact."""

    code: str
    severity: LintSeverity
    message: str


class LintReport(BaseModel):
    """Aggregated lint result for one artifact."""

    artifact: str
    findings: list[LintFinding] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when nothing blocks (no ``error`` findings)."""
        return not any(item.severity == "error" for item in self.findings)

    @property
    def blocking(self) -> list[LintFinding]:
        """Findings that must block the artifact (security/syntax errors)."""
        return [item for item in self.findings if item.severity == "error"]

    @property
    def advisory(self) -> list[LintFinding]:
        """Non-blocking findings (style/quality)."""
        return [item for item in self.findings if item.severity != "error"]

    def summary(self) -> str:
        """One-line-per-finding rendering for prompts and audit entries."""
        return "\n".join(
            f"- [{item.severity}] {item.code}: {item.message}" for item in self.findings
        )


def finding(code: str, severity: LintSeverity, message: str) -> LintFinding:
    """Construct a :class:`LintFinding` (a small convenience for the linters)."""
    return LintFinding(code=code, severity=severity, message=message)
