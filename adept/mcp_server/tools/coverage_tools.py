"""ATT&CK coverage tools exposed over MCP.

These back the Coverage Strategist agent: a technique coverage matrix derived
from the local Sigma ruleset, an importable ATT&CK Navigator layer, prioritised
detection gaps, overlapping/duplicate-rule detection, SIEM field baselines for
noise estimation, and an optional best-effort DeTT&CT bridge.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from adept.coverage import (
    build_coverage_matrix,
    build_navigator_layer,
    find_overlaps,
    generate_layer,
    identify_gaps,
    load_rules,
    profile_fields,
)
from adept.mcp_server.context import AppContext
from adept.mcp_server.siem import SiemBackend
from adept.mcp_server.tools._annotations import READ_ONLY
from adept.shared.errors import AdeptError


def register_coverage_tools(mcp: FastMCP, ctx: AppContext) -> None:
    """Register the ATT&CK coverage tools on the server."""

    def _rules_dir() -> Path:
        base = ctx.settings.sigma.path
        rules = base / "rules"
        return rules if rules.is_dir() else base

    def _resolve(backend: str) -> SiemBackend:
        chosen = ctx.siem_backends.get(backend)
        if chosen is None:
            available = sorted(ctx.siem_backends) or ["(none enabled)"]
            raise ToolError(
                f"SIEM backend '{backend}' is not enabled. Available: {', '.join(available)}"
            )
        return chosen

    @mcp.tool(
        name="build_coverage_matrix",
        title="Build the ATT&CK coverage matrix",
        annotations=READ_ONLY,
    )
    def build_coverage_matrix_tool() -> dict[str, object]:
        """Map the local Sigma ruleset onto ATT&CK and report technique coverage.

        Returns covered techniques (with the rules behind each), overall coverage
        percentage, and any rules that carry no ATT&CK technique tag.
        """
        try:
            rules = load_rules(_rules_dir())
            matrix = build_coverage_matrix(rules, ctx.attack_catalog())
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return matrix.model_dump()

    @mcp.tool(title="Export an ATT&CK Navigator layer", annotations=READ_ONLY)
    def export_navigator_layer(
        name: str = "ADEPT Sigma Coverage",
        description: str = "ATT&CK coverage derived from the local Sigma ruleset.",
    ) -> dict[str, object]:
        """Return an ATT&CK Navigator layer (format v4.5) of current coverage.

        The result can be saved as JSON and imported directly into the MITRE
        ATT&CK Navigator to visualise which techniques the ruleset covers.
        """
        try:
            rules = load_rules(_rules_dir())
            matrix = build_coverage_matrix(rules, ctx.attack_catalog())
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return build_navigator_layer(matrix, name=name, description=description)

    @mcp.tool(title="Identify coverage gaps", annotations=READ_ONLY)
    def identify_coverage_gaps(
        platforms: list[str] | None = None,
        tactics: list[str] | None = None,
    ) -> dict[str, object]:
        """List uncovered ATT&CK techniques, prioritised for detection work.

        Optionally scope by ``platforms`` (e.g. ``Windows``, ``Linux``) and/or
        ``tactics`` (ATT&CK tactic shortnames like ``credential-access``).
        """
        try:
            rules = load_rules(_rules_dir())
            catalog = ctx.attack_catalog()
            matrix = build_coverage_matrix(rules, catalog)
            covered = [cov.technique_id for cov in matrix.techniques]
            report = identify_gaps(covered, catalog, platforms=platforms, tactics=tactics)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return report.model_dump()

    @mcp.tool(title="Find overlapping rules", annotations=READ_ONLY)
    def find_rule_overlaps(min_similarity: float = 0.6) -> dict[str, object]:
        """Find candidate duplicate/overlapping rules before authoring a new one.

        Pairs are flagged when they share an ATT&CK technique or have similar
        detection logic (Jaccard similarity of their field/value signatures within
        the same log source, at or above ``min_similarity``).
        """
        try:
            rules = load_rules(_rules_dir())
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return find_overlaps(rules, min_similarity=min_similarity).model_dump()

    @mcp.tool(title="Profile SIEM field baselines", annotations=READ_ONLY)
    def profile_field_baseline(
        backend: str,
        fields: list[str],
        index: str | None = None,
        lookback_days: int = 7,
        top_n: int = 10,
    ) -> dict[str, object]:
        """Profile field volume/cardinality to anticipate noisy detections.

        For each field, reports total events, distinct values, and the most
        common values over the recent window, flagging high-cardinality fields
        that tend to produce noisy alerts when used as a sole filter.
        """
        siem = _resolve(backend)
        try:
            report = profile_fields(
                siem, fields, index=index, lookback_days=lookback_days, top_n=top_n
            )
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return report.model_dump()

    @mcp.tool(title="Generate a DeTT&CT layer (optional)", annotations=READ_ONLY)
    def dettect_generate_layer(mode: str, yaml_path: str) -> dict[str, object]:
        """Generate an ATT&CK Navigator layer via DeTT&CT (external, best-effort).

        ``mode`` is ``ds`` (data sources), ``v`` (visibility), or ``d``
        (detection); ``yaml_path`` is the DeTT&CT YAML administration file. If
        DeTT&CT is not enabled or not installed, returns ``available: false``
        instead of failing.
        """
        result = generate_layer(ctx.settings.coverage, mode, yaml_path)
        return dataclasses.asdict(result)
