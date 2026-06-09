"""``adept-eval`` — run ADEPT's evaluation harness.

``adept-eval rules`` runs the offline, deterministic component eval (golden Sigma
cases scored with the real matcher) and is safe to run anywhere — no model or
network needed. ``adept-eval scenarios`` runs the LLM-in-the-loop scenarios
against the live agent (Ollama + MCP); every approval gate is auto-rejected so
nothing destructive executes.
"""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from adept.eval.golden import DEFAULT_CASES, run_component_eval
from adept.eval.models import EvalReport, ScenarioResult

app = typer.Typer(
    name="adept-eval",
    help="Run ADEPT's component and scenario evaluations.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _render_report(report: EvalReport) -> None:
    table = Table(title="Component evaluation (golden detection cases)")
    table.add_column("Technique")
    table.add_column("Case")
    for column in ("TP", "FN", "FP", "TN"):
        table.add_column(column, justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right")
    table.add_column("Result")
    for case in report.cases:
        table.add_row(
            case.technique,
            case.name,
            str(case.true_positives),
            str(case.false_negatives),
            str(case.false_positives),
            str(case.true_negatives),
            f"{case.precision:.2f}",
            f"{case.recall:.2f}",
            f"{case.f1:.2f}",
            "[green]pass[/green]" if case.passed else "[red]FAIL[/red]",
        )
    console.print(table)
    console.print(
        f"cases {report.passed_cases}/{report.total_cases} passed · "
        f"precision {report.precision:.2f} · recall {report.recall:.2f} · f1 {report.f1:.2f}"
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
def rules() -> None:
    """Run the offline golden-case component evaluation."""
    report = run_component_eval(DEFAULT_CASES)
    _render_report(report)
    raise typer.Exit(code=0 if report.ok else 1)


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
