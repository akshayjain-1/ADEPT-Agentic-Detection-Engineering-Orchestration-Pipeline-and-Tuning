"""``adept-dac`` — standalone detection-as-code CLI.

Convert, validate and unit-test Sigma rules without the agent or MCP server.
The same library functions back the MCP tools, so CLI and agent behaviour stay
in lock-step.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from adept.detection_as_code.converter import SigmaConverter
from adept.detection_as_code.targets import SIEM_IDS
from adept.detection_as_code.unit_tests import run_test_file
from adept.detection_as_code.validator import RuleValidator
from adept.shared.errors import AdeptError

app = typer.Typer(
    name="adept-dac",
    help="ADEPT detection-as-code: convert, validate and test Sigma rules.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _read(path: Path) -> str:
    if not path.is_file():
        err_console.print(f"[red]error:[/red] file not found: {path}")
        raise typer.Exit(code=2)
    return path.read_text(encoding="utf-8")


@app.command()
def convert(
    rule_file: Annotated[Path, typer.Argument(help="Path to a Sigma rule YAML file.")],
    siem: Annotated[str, typer.Option(help="Target SIEM id (elk, opensearch, splunk).")] = "elk",
    pipeline: Annotated[
        list[str] | None,
        typer.Option(help="Override pipeline(s): built-in name or YAML path. Repeatable."),
    ] = None,
) -> None:
    """Convert a Sigma rule to a SIEM query language."""
    if siem not in SIEM_IDS:
        err_console.print(f"[red]error:[/red] unknown SIEM {siem!r}; choose from {list(SIEM_IDS)}")
        raise typer.Exit(code=2)
    try:
        result = SigmaConverter(pipeline_dir=Path.cwd()).convert(
            _read(rule_file), siem, pipelines=pipeline
        )
    except AdeptError as exc:
        err_console.print(f"[red]conversion failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold]{siem}[/bold] ({result.query_language}) pipelines={result.pipelines or ['<none>']}"
    )
    for query in result.queries:
        console.print(query)


@app.command()
def validate(
    rule_file: Annotated[Path, typer.Argument(help="Path to a Sigma rule YAML file.")],
) -> None:
    """Validate a Sigma rule and report any issues. Exits non-zero on error."""
    report = RuleValidator().validate_text(_read(rule_file))
    if not report.issues:
        console.print(f"[green]OK[/green] — {report.rule_count} rule(s), no issues.")
        return

    table = Table("severity", "check", "message", title=f"{rule_file}")
    for issue in report.issues:
        colour = {"high": "red", "medium": "yellow", "low": "cyan"}[issue.severity]
        table.add_row(f"[{colour}]{issue.severity}[/{colour}]", issue.check, issue.message)
    console.print(table)
    if not report.ok:
        raise typer.Exit(code=1)


@app.command()
def test(
    path: Annotated[Path, typer.Argument(help="A test YAML file or a directory of test files.")],
) -> None:
    """Run TP/FP sample-event unit tests. Exits non-zero on any failure."""
    test_files = sorted(path.rglob("*.yml")) if path.is_dir() else [path]
    if not test_files:
        err_console.print(f"[red]error:[/red] no test files found at {path}")
        raise typer.Exit(code=2)

    failures = 0
    for test_file in test_files:
        try:
            report = run_test_file(test_file)
        except AdeptError as exc:
            err_console.print(f"[red]{test_file}: {exc}[/red]")
            failures += 1
            continue
        status = "[green]PASS[/green]" if report.ok else "[red]FAIL[/red]"
        console.print(f"{status} {report.rule} ({report.passed}/{report.total})")
        for case in report.cases:
            if not case.passed:
                console.print(
                    f"    [red]x[/red] {case.kind} {case.name!r}: "
                    f"expected match={case.expected_match}, got {case.actual_match}"
                )
        failures += 0 if report.ok else 1

    if failures:
        raise typer.Exit(code=1)


if __name__ == "__main__":  # pragma: no cover
    app()
