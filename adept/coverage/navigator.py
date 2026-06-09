"""Render a coverage matrix as an ATT&CK Navigator layer (format v4.5).

The output dict conforms to the MITRE ATT&CK Navigator Layer File Format v4.5 and
can be imported directly into the Navigator UI.
"""

from __future__ import annotations

from adept.coverage.models import CoverageMatrix

# Verified against the official spec: layer must be "4.5"; navigator must be
# >= "4.9.0" (5.2.0 is the current release). The ATT&CK version is optional.
LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.2.0"
# White -> blue gradient: deeper blue = more rules mapped to the technique.
GRADIENT_COLORS = ["#ffffff", "#66b1ff", "#1f4e9c"]


def build_navigator_layer(
    matrix: CoverageMatrix,
    *,
    name: str = "ADEPT Sigma Coverage",
    description: str = "ATT&CK coverage derived from the local Sigma ruleset.",
    attack_version: str = "",
) -> dict[str, object]:
    """Convert a :class:`CoverageMatrix` into a Navigator layer dict."""
    versions: dict[str, str] = {"navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION}
    if attack_version:
        versions["attack"] = attack_version

    techniques: list[dict[str, object]] = []
    for cov in matrix.techniques:
        titles = ", ".join(cov.rule_titles)
        techniques.append(
            {
                "techniqueID": cov.technique_id,
                "score": cov.rule_count,
                "enabled": True,
                "color": "",
                "comment": f"{cov.rule_count} ADEPT rule(s): {titles}",
            }
        )

    max_score = max((cov.rule_count for cov in matrix.techniques), default=1)
    return {
        "name": name,
        "versions": versions,
        "domain": matrix.domain,
        "description": description,
        "techniques": techniques,
        "gradient": {
            "colors": GRADIENT_COLORS,
            "minValue": 0,
            "maxValue": max(max_score, 1),
        },
        "legendItems": [],
        "hideDisabled": False,
    }
