"""Detection-as-code tools exposed over MCP.

These let the Rule Author and Validator/DaC agents convert Sigma rules to each
SIEM's query language, validate them, list available conversion targets, run a
rule's TP/FP unit tests, and backtest a rule against real historical logs (the
last feeding the human approval packet). The same library backs the
``adept-dac`` CLI, so MCP and CLI behaviour are identical.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from sigma.plugins import InstalledSigmaPlugins

from adept.detection_as_code.backtest import backtest_rule
from adept.detection_as_code.converter import SigmaConverter
from adept.detection_as_code.targets import (
    SIEM_CONVERTER_TARGETS,
    SIEM_QUERY_LANGUAGE,
)
from adept.detection_as_code.unit_tests import run_test_file
from adept.detection_as_code.validator import RuleValidator
from adept.mcp_server.context import AppContext
from adept.mcp_server.siem import SiemBackend
from adept.mcp_server.tools._annotations import READ_ONLY
from adept.shared.errors import AdeptError


def register_dac_tools(mcp: FastMCP, ctx: AppContext) -> None:
    """Register the detection-as-code tools on the server."""
    # Confine pipeline file specs to the Sigma repo's ``pipelines/`` directory so
    # a model-supplied ``pipelines`` argument cannot read arbitrary files.
    converter = SigmaConverter(pipeline_dir=ctx.settings.sigma.path / "pipelines")
    validator = RuleValidator()

    def _resolve(backend: str) -> SiemBackend:
        chosen = ctx.siem_backends.get(backend)
        if chosen is None:
            available = sorted(ctx.siem_backends) or ["(none enabled)"]
            raise ToolError(
                f"SIEM backend '{backend}' is not enabled. Available: {', '.join(available)}"
            )
        return chosen

    @mcp.tool(title="Convert a Sigma rule to a SIEM query", annotations=READ_ONLY)
    def convert_sigma_rule(
        rule_text: str,
        siem: str,
        pipelines: list[str] | None = None,
    ) -> dict[str, object]:
        """Convert a Sigma rule (YAML) into the query language of ``siem``.

        ``siem`` is one of ``elk``/``opensearch``/``splunk``. ``pipelines``
        optionally overrides the default pipeline policy with built-in pipeline
        names or YAML paths.
        """
        try:
            result = converter.convert(rule_text, siem, pipelines=pipelines)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()

    @mcp.tool(title="Validate a Sigma rule", annotations=READ_ONLY)
    def validate_sigma_rule(rule_text: str) -> dict[str, object]:
        """Validate a Sigma rule and return any structural or lint issues."""
        return validator.validate_text(rule_text).model_dump()

    @mcp.tool(title="List conversion targets and pipelines", annotations=READ_ONLY)
    def list_conversion_targets() -> dict[str, object]:
        """List the SIEM conversion targets and available pySigma pipelines."""
        plugins = InstalledSigmaPlugins.autodiscover()
        return {
            "siems": [
                {
                    "id": siem_id,
                    "target": target,
                    "query_language": SIEM_QUERY_LANGUAGE.get(siem_id, target),
                }
                for siem_id, target in SIEM_CONVERTER_TARGETS.items()
            ],
            "pipelines": sorted(plugins.pipelines),
        }

    @mcp.tool(title="Run a rule's TP/FP unit tests", annotations=READ_ONLY)
    def run_rule_unit_tests(test_path: str) -> dict[str, object]:
        """Run the true/false-positive unit tests defined in a test file.

        ``test_path`` is resolved relative to the Sigma repository root. The
        file names the rule under test and lists sample events that must (TP)
        or must not (FP) match.
        """
        repo_root = Path(ctx.settings.sigma.path)
        resolved = (repo_root / test_path).resolve()
        try:
            resolved.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise ToolError("test_path must be inside the Sigma repository") from exc
        if not resolved.is_file():
            raise ToolError(f"test file not found: {test_path}")
        try:
            report = run_test_file(resolved, repo_root=repo_root)
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return report.model_dump()

    @mcp.tool(title="Backtest a rule against historical logs", annotations=READ_ONLY)
    def backtest_sigma_rule(
        rule_text: str,
        backend: str,
        index: str | None = None,
        lookback_days: int = 7,
    ) -> dict[str, object]:
        """Estimate a rule's alert volume by replaying it over recent SIEM data.

        Converts the rule for ``backend`` and runs it over the last
        ``lookback_days`` days, returning the match count and an estimated daily
        volume for the human approval packet.
        """
        siem = _resolve(backend)
        try:
            result = backtest_rule(
                rule_text,
                siem,
                converter=converter,
                index=index,
                lookback_days=lookback_days,
            )
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return result.model_dump()
