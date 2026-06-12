"""Deterministic linter for exported ATT&CK Navigator layer JSON."""

from __future__ import annotations

import json
from collections.abc import Mapping

from adept.guardrails.models import LintFinding, LintReport, finding

_NAV_DOMAINS = frozenset({"enterprise-attack", "mobile-attack", "ics-attack"})


def lint_navigator_layer(layer: str | Mapping[str, object]) -> LintReport:
    """Lint a Navigator layer for required fields and basic structure."""
    if isinstance(layer, str):
        try:
            parsed: object = json.loads(layer)
        except json.JSONDecodeError as exc:
            return LintReport(
                artifact="navigator",
                findings=[finding("navigator.invalid_json", "error", f"Layer is not valid JSON: {exc}")],
            )
    else:
        parsed = layer
    if not isinstance(parsed, Mapping):
        return LintReport(
            artifact="navigator",
            findings=[finding("navigator.not_object", "error", "Navigator layer must be a JSON object.")],
        )

    findings: list[LintFinding] = []
    for key in ("name", "versions", "domain", "techniques"):
        if key not in parsed:
            findings.append(
                finding("navigator.missing_field", "error", f"Layer is missing required field '{key}'.")
            )
    versions = parsed.get("versions")
    if isinstance(versions, Mapping) and "layer" not in versions:
        findings.append(
            finding(
                "navigator.missing_layer_version",
                "error",
                "versions.layer is required by the Navigator layer format.",
            )
        )
    domain = parsed.get("domain")
    if isinstance(domain, str) and domain and domain not in _NAV_DOMAINS:
        findings.append(
            finding("navigator.unknown_domain", "warning", f"Unusual ATT&CK domain {domain!r}.")
        )
    techniques = parsed.get("techniques")
    if techniques is not None and not isinstance(techniques, list):
        findings.append(finding("navigator.bad_techniques", "error", "'techniques' must be a list."))
    elif isinstance(techniques, list):
        for index, technique in enumerate(techniques):
            if not isinstance(technique, Mapping) or not technique.get("techniqueID"):
                findings.append(
                    finding(
                        "navigator.bad_technique",
                        "error",
                        f"techniques[{index}] is missing 'techniqueID'.",
                    )
                )
                break
    return LintReport(artifact="navigator", findings=findings)
