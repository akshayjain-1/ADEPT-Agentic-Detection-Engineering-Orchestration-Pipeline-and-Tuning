"""``adept-coverage`` — standalone ATT&CK coverage CLI.

Build a coverage matrix, export an ATT&CK Navigator layer, list prioritised
gaps, find overlapping rules, profile SIEM field baselines, and drive the
optional DeTT&CT bridge — all without the agent or MCP server. The same library
functions back the MCP coverage tools, so CLI and agent behaviour stay aligned.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from adept.config.settings import get_settings
from adept.coverage import (
    AttackCatalog,
    build_coverage_matrix,
    build_navigator_layer,
    find_overlaps,
    generate_layer,
    identify_gaps,
    load_rules,
    profile_fields,
)
from adept.intel.service import IntelService
from adept.shared.errors import AdeptError

app = typer.Typer(
    name="adept-coverage",
    help="ADEPT ATT&CK coverage: matrix, Navigator layer, gaps, overlap, baseline.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _default_rules_dir() -> Path:
    """Return the configured Sigma rules directory."""
    base = get_settings().sigma.path
    rules = base / "rules"
    return rules if rules.is_dir() else base


def _load_catalog(bundle: Path | None) -> AttackCatalog:
    """Build the ATT&CK catalogue from ``bundle`` or the cached intel bundle."""
    if bundle is not None:
        if not bundle.is_file():
            err_console.print(f"[red]error:[/red] STIX bundle not found: {bundle}")
            raise typer.Exit(code=2)
        return AttackCatalog.from_file(str(bundle))

    intel = IntelService.from_settings(get_settings())
    try:
        path = intel.attack.ensure_bundle_path()
    finally:
        intel.close()
    return AttackCatalog.from_file(str(path))


@app.command()
def matrix(
    rules_dir: Annotated[Path | None, typer.Argument(help="Sigma rules directory.")] = None,
    bundle: Annotated[Path | None, typer.Option(help="ATT&CK STIX bundle path.")] = None,
    navigator_out: Annotated[
        Path | None, typer.Option(help="Write an ATT&CK Navigator layer JSON here.")
    ] = None,
    name: Annotated[str, typer.Option(help="Navigator layer name.")] = "ADEPT Sigma Coverage",
) -> None:
    """Show ATT&CK technique coverage of the local Sigma ruleset."""
    rules_path = rules_dir or _default_rules_dir()
    try:
        rules = load_rules(rules_path)
        cov = build_coverage_matrix(rules, _load_catalog(bundle))
    except AdeptError as exc:
        err_console.print(f"[red]coverage failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold]Coverage[/bold]: {cov.covered_techniques}/{cov.total_techniques} "
        f"techniques ([green]{cov.coverage_pct}%[/green])"
    )
    table = Table("technique", "name", "rules", title="Covered techniques")
    for technique in cov.techniques[:50]:
        table.add_row(technique.technique_id, technique.name, str(technique.rule_count))
    console.print(table)
    if cov.untagged_rules:
        console.print(f"[yellow]{len(cov.untagged_rules)}[/yellow] rule(s) without an ATT&CK tag.")

    if navigator_out is not None:
        layer = build_navigator_layer(cov, name=name)
        navigator_out.write_text(json.dumps(layer, indent=2), encoding="utf-8")
        console.print(f"Navigator layer written to [bold]{navigator_out}[/bold].")


@app.command()
def gaps(
    rules_dir: Annotated[Path | None, typer.Argument(help="Sigma rules directory.")] = None,
    bundle: Annotated[Path | None, typer.Option(help="ATT&CK STIX bundle path.")] = None,
    platform: Annotated[
        list[str] | None, typer.Option(help="Scope by ATT&CK platform. Repeatable.")
    ] = None,
    tactic: Annotated[
        list[str] | None, typer.Option(help="Scope by ATT&CK tactic shortname. Repeatable.")
    ] = None,
    limit: Annotated[int, typer.Option(help="Maximum gaps to display.")] = 40,
) -> None:
    """List uncovered ATT&CK techniques, prioritised for detection work."""
    rules_path = rules_dir or _default_rules_dir()
    try:
        rules = load_rules(rules_path)
        catalog = _load_catalog(bundle)
        cov = build_coverage_matrix(rules, catalog)
        report = identify_gaps(
            [technique.technique_id for technique in cov.techniques],
            catalog,
            platforms=platform,
            tactics=tactic,
        )
    except AdeptError as exc:
        err_console.print(f"[red]gap analysis failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[bold]{report.total_gaps}[/bold] gap(s); scope={report.scope}")
    table = Table("priority", "technique", "name", "tactics", title="Detection gaps")
    colours = {"high": "red", "medium": "yellow", "low": "cyan"}
    for gap in report.gaps[:limit]:
        colour = colours[gap.priority]
        table.add_row(
            f"[{colour}]{gap.priority}[/{colour}]",
            gap.technique_id,
            gap.name,
            ", ".join(gap.tactics),
        )
    console.print(table)


@app.command()
def overlap(
    rules_dir: Annotated[Path | None, typer.Argument(help="Sigma rules directory.")] = None,
    min_similarity: Annotated[
        float, typer.Option(help="Minimum signature similarity to flag (0-1).")
    ] = 0.6,
) -> None:
    """Find candidate duplicate/overlapping rules in the ruleset."""
    rules_path = rules_dir or _default_rules_dir()
    try:
        report = find_overlaps(load_rules(rules_path), min_similarity=min_similarity)
    except AdeptError as exc:
        err_console.print(f"[red]overlap analysis failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[bold]{report.total}[/bold] overlapping pair(s).")
    table = Table("rule A", "rule B", "shared techniques", "similarity", title="Rule overlap")
    for pair in report.pairs:
        table.add_row(
            pair.rule_a,
            pair.rule_b,
            ", ".join(pair.shared_techniques) or "-",
            str(pair.field_similarity),
        )
    console.print(table)


@app.command()
def baseline(
    field: Annotated[list[str] | None, typer.Option(help="Field to profile. Repeatable.")] = None,
    siem: Annotated[str, typer.Option(help="SIEM backend id (elk, opensearch, splunk).")] = "elk",
    index: Annotated[str | None, typer.Option(help="Index/pattern to profile.")] = None,
    lookback_days: Annotated[int, typer.Option(help="Days of history to profile.")] = 7,
    top_n: Annotated[int, typer.Option(help="Top values to report per field.")] = 10,
) -> None:
    """Profile SIEM field volume/cardinality to anticipate noisy detections."""
    if not field:
        err_console.print("[red]error:[/red] at least one --field is required.")
        raise typer.Exit(code=2)

    from adept.mcp_server.siem import build_backends

    backend = build_backends(get_settings()).get(siem)
    if backend is None:
        err_console.print(f"[red]error:[/red] SIEM backend {siem!r} is not enabled.")
        raise typer.Exit(code=2)

    try:
        report = profile_fields(
            backend, field, index=index, lookback_days=lookback_days, top_n=top_n
        )
    except AdeptError as exc:
        err_console.print(f"[red]baseline failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table("field", "events", "distinct", "noisy", "note", title=f"{siem} field baseline")
    for profile in report.fields:
        table.add_row(
            profile.field,
            str(profile.total_events),
            str(profile.distinct_values),
            "[red]yes[/red]" if profile.noisy else "no",
            profile.note,
        )
    console.print(table)


@app.command()
def dettect(
    mode: Annotated[str, typer.Argument(help="DeTT&CT mode: ds, v, or d.")],
    yaml_file: Annotated[Path, typer.Argument(help="DeTT&CT YAML administration file.")],
) -> None:
    """Generate an ATT&CK Navigator layer via DeTT&CT (optional, best-effort)."""
    result = generate_layer(get_settings().coverage, mode, yaml_file)
    if not result.available:
        err_console.print(f"[yellow]DeTT&CT not available:[/yellow] {result.message}")
        raise typer.Exit(code=1)
    if not result.ok:
        err_console.print(f"[red]DeTT&CT failed:[/red] {result.message}")
        if result.stderr_tail:
            err_console.print(result.stderr_tail)
        raise typer.Exit(code=1)
    console.print(f"[green]OK[/green] — generated layer(s): {result.layer_files or '<none found>'}")


if __name__ == "__main__":  # pragma: no cover
    app()
