"""Structural validation and linting of Sigma rules.

Equivalent to ``sigma check``: parse the rule (catching structural errors) and
run pySigma's built-in rule validators, returning a structured report. The
MCP tool layer and the DaC CLI both consume this.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import cached_property
from typing import cast

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.plugins import InstalledSigmaPlugins
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from adept.detection_as_code.models import IssueSeverity, ValidationIssue, ValidationReport

_SEVERITY_MAP: dict[SigmaValidationIssueSeverity, IssueSeverity] = {
    SigmaValidationIssueSeverity.LOW: "low",
    SigmaValidationIssueSeverity.MEDIUM: "medium",
    SigmaValidationIssueSeverity.HIGH: "high",
}


def _issue_to_model(issue: SigmaValidationIssue) -> ValidationIssue:
    severity = _SEVERITY_MAP.get(issue.severity, "low")
    return ValidationIssue(
        check=type(issue).__name__,
        severity=severity,
        message=str(getattr(issue, "description", type(issue).__name__)),
        rule_ids=[str(rule.id) for rule in issue.rules if rule.id is not None],
    )


class RuleValidator:
    """Validate Sigma rules using all installed pySigma validators."""

    @cached_property
    def _validator(self) -> SigmaValidator:
        plugins = InstalledSigmaPlugins.autodiscover()
        # ``validators`` values are validator *classes* at runtime; the upstream
        # annotation says instances, so cast for the strictly-typed constructor.
        validators = cast("list[type[SigmaRuleValidator]]", list(plugins.validators.values()))
        return SigmaValidator(validators)

    def validate_text(self, rule_text: str) -> ValidationReport:
        """Validate one or more Sigma rules supplied as YAML text."""
        try:
            collection = SigmaCollection.from_yaml(rule_text)
        except (SigmaError, yaml.YAMLError) as exc:
            return ValidationReport(
                ok=False,
                rule_count=0,
                issues=[
                    ValidationIssue(
                        check="SigmaParseError",
                        severity="high",
                        message=str(exc),
                    )
                ],
            )
        return self._validate_collection(collection)

    def _validate_collection(self, collection: SigmaCollection) -> ValidationReport:
        raw_issues = self._validator.validate_rules(
            cast("Iterator[SigmaRule]", iter(collection.rules))
        )
        issues = [_issue_to_model(issue) for issue in raw_issues]
        has_error = any(issue.severity == "high" for issue in issues)
        return ValidationReport(
            ok=not has_error,
            rule_count=len(collection.rules),
            issues=issues,
        )
