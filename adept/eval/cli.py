"""``adept-eval`` — run ADEPT's evaluation harness.

``adept-eval rules`` runs TP/FP unit tests from ``sigma_rules/tests/`` against
the local Sigma rule files and is safe to run anywhere — no model or network
needed. ``adept-eval scenarios`` runs the LLM-in-the-loop scenarios against the
live agent (Ollama + MCP); every approval gate is auto-rejected so nothing
destructive executes.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from adept.detection_as_code.models import UnitTestReport
from adept.detection_as_code.unit_tests import run_test_file
from adept.eval.models import ScenarioResult

app = typer.Typer(
    name="adept-eval",
    help="Run ADEPT's unit-test and scenario evaluations.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _render_unit_tests(reports: list[UnitTestReport]) -> None:
    table = Table(title="Sigma rule unit tests (TP/FP)")
    table.add_column("Rule")
    table.add_column("Total", justify="right")
    table.add_column("Passed", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Result")
    for report in reports:
        table.add_row(
            report.rule,
            str(report.total),
            str(report.passed),
            str(report.failed),
            "[green]pass[/green]" if report.ok else "[red]FAIL[/red]",
        )
        for case in report.cases:
            if not case.passed:
                table.add_row(
                    f"  [dim]{case.name}[/dim]",
                    "",
                    "",
                    "",
                    f"[red]expected {'match' if case.expected_match else 'no match'}[/red]",
                )
    console.print(table)
    total_cases = sum(r.total for r in reports)
    total_passed = sum(r.passed for r in reports)
    rules_ok = sum(1 for r in reports if r.ok)
    console.print(
        f"rules {rules_ok}/{len(reports)} passed · cases {total_passed}/{total_cases}"
    )


def _render_scenarios(results: list[ScenarioResult]) -> None:
    table = Table(title="Scenario evaluation (LLM-in-the-loop)")
    table.add_column("Scenario")
    table.add_column("Score", justify="right")
    table.add_column("Result")
    table.add_column("Failing checks")
    for result in results:
        failing = "; ".join(
            f"{check.name}: {check.detail or 'failed'}"
            for check in result.checks
            if not check.passed
        )
        table.add_row(
            result.id,
            f"{result.score:.2f}",
            "[green]pass[/green]" if result.passed else "[red]FAIL[/red]",
            failing or "-",
        )
    console.print(table)


@app.command("rules")
def rules(
    tests_dir: Annotated[
        Path,
        typer.Argument(help="Directory containing sigma test YAML files."),
    ] = Path("sigma_rules/tests"),
) -> None:
    """Run TP/FP unit tests from sigma_rules/tests/ (fully offline)."""
    from adept.shared.errors import AdeptError

    tests_path = tests_dir.resolve()
    if not tests_path.is_dir():
        err_console.print(f"[red]tests directory not found:[/red] {tests_path}")
        raise typer.Exit(code=2)

    test_files = sorted(tests_path.glob("*.yml"))
    if not test_files:
        err_console.print(f"[yellow]no test files found in[/yellow] {tests_path}")
        raise typer.Exit(code=0)

    reports: list[UnitTestReport] = []
    for path in test_files:
        try:
            reports.append(run_test_file(path))
        except AdeptError as exc:
            err_console.print(f"[red]{path.name}:[/red] {exc}")
            raise typer.Exit(code=2) from exc

    _render_unit_tests(reports)
    raise typer.Exit(code=0 if all(r.ok for r in reports) else 1)


@app.command("scenarios")
def scenarios(
    auto_approve: Annotated[
        bool,
        typer.Option(help="Reserved; scenarios always auto-reject approval gates."),
    ] = False,
) -> None:
    """Run the LLM scenarios against the live agent (requires Ollama + MCP)."""
    from adept.agent.service import open_agent_session
    from adept.config.settings import get_settings
    from adept.eval.scenarios import DEFAULT_SCENARIOS, run_scenarios
    from adept.shared.errors import AdeptError

    _ = auto_approve

    async def _run() -> list[ScenarioResult]:
        settings = get_settings()
        async with open_agent_session(settings) as session:
            return await run_scenarios(session, DEFAULT_SCENARIOS)

    try:
        results = asyncio.run(_run())
    except AdeptError as exc:
        err_console.print(f"[red]eval failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    _render_scenarios(results)
    raise typer.Exit(code=0 if all(result.passed for result in results) else 1)


if __name__ == "__main__":
    app()
