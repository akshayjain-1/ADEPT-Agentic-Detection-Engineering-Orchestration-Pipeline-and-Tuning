"""Deterministic linter for Sigma rule YAML.

Wraps the existing pySigma-backed :class:`RuleValidator` (so structural and
lint issues are reported with their real severity) and adds the prompt-mandated
authoring rules: exactly one document per rule, a real unique UUID id (never a
placeholder), and a descriptive title.
"""

from __future__ import annotations

import re

import yaml

from adept.detection_as_code.models import IssueSeverity, ValidationReport
from adept.detection_as_code.validator import RuleValidator
from adept.guardrails.models import LintFinding, LintReport, LintSeverity, finding

_SEVERITY_TO_LINT: dict[IssueSeverity, LintSeverity] = {
    "high": "error",
    "medium": "warning",
    "low": "info",
}
#: RFC-4122 UUID (any version 1-5); a real id rather than a placeholder.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_PLACEHOLDER_HINTS = ("xxxx", "placeholder", "your-", "todo", "example", "<", "uuid")


def lint_sigma(rule_text: str, *, validator: RuleValidator | None = None) -> LintReport:
    """Lint a Sigma rule's structure, validators, id, and title."""
    active = validator if validator is not None else RuleValidator()
    report: ValidationReport = active.validate_text(rule_text)
    findings: list[LintFinding] = [
        finding(
            f"sigma.{issue.check}",
            _SEVERITY_TO_LINT.get(issue.severity, "info"),
            issue.message,
        )
        for issue in report.issues
    ]
    try:
        docs = [doc for doc in yaml.safe_load_all(rule_text) if isinstance(doc, dict)]
    except yaml.YAMLError:
        docs = []  # the validator already reported the parse error above
    if len(docs) > 1:
        findings.append(
            finding(
                "sigma.multiple_documents",
                "error",
                "Emit exactly one Sigma rule document (no '---' separators); write_sigma_rule "
                "names the file from a single rule's title and logsource.",
            )
        )
    for doc in docs:
        findings.extend(_id_and_title_findings(doc))
    return LintReport(artifact="sigma", findings=findings)


def _id_and_title_findings(doc: dict[object, object]) -> list[LintFinding]:
    findings: list[LintFinding] = []
    rule_id = str(doc.get("id", "")).strip()
    if not rule_id:
        findings.append(
            finding("sigma.missing_id", "error", "Rule is missing a unique 'id' (a UUIDv4).")
        )
    elif not _UUID_RE.match(rule_id):
        findings.append(
            finding(
                "sigma.placeholder_id",
                "error",
                f"Rule 'id' {rule_id!r} is not a real UUID; generate a fresh unique UUIDv4.",
            )
        )
    title = str(doc.get("title", "")).strip()
    if not title:
        findings.append(
            finding("sigma.missing_title", "warning", "Rule is missing a descriptive 'title'.")
        )
    elif any(hint in title.lower() for hint in _PLACEHOLDER_HINTS):
        findings.append(
            finding(
                "sigma.placeholder_title",
                "warning",
                f"Rule 'title' {title!r} looks like a placeholder.",
            )
        )
    return findings
