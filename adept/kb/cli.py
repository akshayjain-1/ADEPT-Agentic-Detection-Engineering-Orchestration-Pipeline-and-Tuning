"""``adept-kb`` — standalone knowledge-base CLI.

Ingest local and optional SigmaHQ corpora into the Chroma vector store and run
semantic searches against them. The same library backs the MCP ``search_knowledge_base``
tool, so CLI and agent retrieval stay aligned. Ingestion and search require a
running Ollama server for embeddings.
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from adept.config.settings import get_settings
from adept.kb.service import ALL_SOURCES, KnowledgeBase
from adept.shared.errors import AdeptError

app = typer.Typer(
    name="adept-kb",
    help="ADEPT knowledge base: ingest corpora and search them semantically.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _knowledge_base() -> KnowledgeBase:
    return KnowledgeBase.from_settings(get_settings())


@app.command()
def ingest(
    source: Annotated[
        list[str] | None,
        typer.Option(help=f"Sources to ingest (repeatable). Choices: {', '.join(ALL_SOURCES)}."),
    ] = None,
) -> None:
    """Index the selected corpora into the vector store (default: all available)."""
    kb = _knowledge_base()
    try:
        report = kb.ingest(source)
    except AdeptError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    finally:
        kb.close()

    table = Table(title=f"Ingested into '{report.collection}'")
    table.add_column("Source")
    table.add_column("Documents", justify="right")
    for name in report.sources:
        if name in report.by_source:
            table.add_row(name, str(report.by_source[name]))
        else:
            table.add_row(name, "[yellow]skipped[/yellow]")
    console.print(table)
    console.print(f"Total indexed: [bold]{report.total_indexed}[/bold]")


@app.command()
def search(
    query: Annotated[str, typer.Argument(help="Natural-language search query.")],
    source: Annotated[
        list[str] | None, typer.Option(help="Restrict to these sources (repeatable).")
    ] = None,
    limit: Annotated[int, typer.Option(help="Maximum results.")] = 5,
) -> None:
    """Search the knowledge base and print the ranked matches."""
    kb = _knowledge_base()
    try:
        result = kb.search(query, n_results=limit, sources=source)
    except AdeptError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    finally:
        kb.close()

    if not result.hits:
        console.print("[yellow]No matches.[/yellow]")
        return
    table = Table(title=f"Results for: {query}")
    table.add_column("Score", justify="right")
    table.add_column("Source")
    table.add_column("Title")
    for hit in result.hits:
        table.add_row(f"{hit.score:.3f}", hit.source, hit.title or hit.id)
    console.print(table)


@app.command()
def info() -> None:
    """Show the collection name and indexed document count."""
    settings = get_settings()
    kb = _knowledge_base()
    try:
        count = kb.count()
    except AdeptError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    finally:
        kb.close()
    console.print(f"Collection: [bold]{settings.kb.collection}[/bold]")
    console.print(f"Persist dir: {settings.kb.persist_dir}")
    console.print(f"Embed model: {settings.kb.embed_model}")
    console.print(f"Documents: [bold]{count}[/bold]")


if __name__ == "__main__":  # pragma: no cover
    app()
