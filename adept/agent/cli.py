"""``adept`` — interactive detection-engineering agent CLI.

Starts a rich REPL backed by the LangGraph supervisor graph. Conversations are
persisted per named thread in the SQLite checkpointer, so sessions can be
resumed. State-changing tools pause for human approval, rendered inline.

The agent requires a reachable MCP server (for tools) and Ollama (for the model);
neither is contacted until a session is opened.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated, Any

import typer
from langchain_core.messages import AIMessage
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax

from adept.agent.approval import ApprovalDecision, ApprovalRequest
from adept.agent.audit import AuditLog
from adept.agent.history import list_threads, new_thread_id
from adept.agent.service import ProgressEvent, open_agent_session
from adept.agent.specialists import SPECIALISTS
from adept.agent.supervisor import FINISH, message_text
from adept.config.settings import Settings, get_settings
from adept.shared.errors import AdeptError
from adept.shared.notify import Notifier

app = typer.Typer(
    name="adept",
    help="ADEPT autonomous detection-engineering agent.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

#: Specialist names usable in an ``@specialist`` routing override.
_SPECIALIST_NAMES: tuple[str, ...] = tuple(spec.name for spec in SPECIALISTS)

COMMANDS_HELP = (
    "Commands: :help  :threads  :new  :thread <id>  :quit\n"
    "Force a specialist by starting a message with @name "
    f"({', '.join(_SPECIALIST_NAMES)})."
)


def _parse_mention(text: str, valid: set[str]) -> tuple[str | None, str]:
    """Split a leading ``@specialist`` mention from a user message.

    Returns ``(specialist, remaining_text)`` when ``text`` begins with
    ``@<name>`` (case-insensitive) naming a known specialist, otherwise
    ``(None, text)`` so the message routes normally and any literal leading
    ``@`` is preserved.
    """
    if not text.startswith("@"):
        return None, text
    tokens = text[1:].split(maxsplit=1)
    if not tokens:
        return None, text
    match = next((name for name in valid if name.lower() == tokens[0].lower()), None)
    if match is None:
        return None, text
    return match, tokens[1].strip() if len(tokens) > 1 else ""


def _resolve_editor(settings: Settings) -> str:
    return settings.agent.editor or os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano"


def _edit_arguments(arguments: dict[str, Any], *, editor: str) -> dict[str, Any]:
    """Open ``arguments`` as JSON in ``editor`` and return the parsed result."""
    with tempfile.NamedTemporaryFile(
        "w+", suffix=".json", delete=False, encoding="utf-8"
    ) as handle:
        json.dump(arguments, handle, indent=2, default=str)
        handle.flush()
        temp_path = Path(handle.name)
    try:
        subprocess.run([editor, str(temp_path)], check=True)  # noqa: S603
        edited = temp_path.read_text(encoding="utf-8")
    finally:
        temp_path.unlink(missing_ok=True)
    try:
        parsed = json.loads(edited)
    except json.JSONDecodeError:
        err_console.print("[yellow]Could not parse edited JSON; keeping original arguments.[/]")
        return arguments
    if not isinstance(parsed, dict):
        err_console.print("[yellow]Edited content was not a JSON object; keeping arguments.[/]")
        return arguments
    return parsed


def _render_request(request: ApprovalRequest) -> None:
    body = json.dumps(request.arguments, indent=2, default=str)
    console.print(
        Panel(
            Syntax(body, "json", theme="ansi_dark", word_wrap=True),
            title=f"Approval required: {request.tool}",
            subtitle=request.summary,
            border_style="yellow",
        )
    )


def _make_interrupt_handler(settings: Settings) -> Any:
    notifier = Notifier(settings.notify)

    async def handler(payload: dict[str, Any]) -> ApprovalDecision:
        request = ApprovalRequest.model_validate(payload)
        # Best-effort push so a remote operator knows an approval is waiting
        # (a no-op unless a notification backend is configured).
        await notifier.send(
            f"ADEPT approval required: {request.tool}",
            request.summary,
            level="warning",
        )
        _render_request(request)
        choice = (
            console.input("[bold yellow]approve / reject / edit / changes >[/] ").strip().lower()
        )
        if choice.startswith("a"):
            decision = ApprovalDecision(action="approve")
        elif choice.startswith("e"):
            edited = _edit_arguments(request.arguments, editor=_resolve_editor(settings))
            decision = ApprovalDecision(action="edit", edited_arguments=edited)
        elif choice.startswith("c"):
            feedback = console.input("[bold]Describe the changes you want >[/] ").strip()
            decision = ApprovalDecision(action="request_changes", feedback=feedback)
        else:
            decision = ApprovalDecision(action="reject")
        if decision.action in ("approve", "edit"):
            await notifier.send(
                f"ADEPT action approved: {request.tool}",
                request.summary,
                level="critical",
            )
        return decision

    return handler


def _render_progress(event: ProgressEvent) -> None:
    """Show the live stage of a turn instead of raw HTTP traffic."""
    if event.kind == "route":
        if event.label == FINISH:
            return
        console.print(f"[cyan]→[/] delegating to [bold]{event.label}[/]")
    elif event.kind == "specialist" and event.tools:
        used = ", ".join(dict.fromkeys(event.tools))
        console.print(f"   [dim]• {event.label} used {used}[/]")
    elif event.kind == "evaluate":
        if event.label.startswith("regenerate:"):
            spec = event.label.split(":", 1)[1]
            console.print(f"   [yellow]• review flagged issues; asking {spec} to revise[/]")
        elif event.label == "escalated":
            console.print("   [yellow]• review issues unresolved; see notes above[/]")
        else:  # passed
            console.print("   [dim]• review passed[/]")


def _print_response(result: dict[str, Any]) -> None:
    for message in reversed(result.get("messages", [])):
        if isinstance(message, AIMessage):
            text = message_text(message)
            if text.strip():
                console.print(Panel(text, title="adept", border_style="cyan"))
                return
    console.print("[dim](no response)[/]")


def _print_threads(settings: Settings) -> None:
    threads = list_threads(settings.agent.checkpoint_db)
    if not threads:
        console.print("[dim]No saved threads yet.[/]")
        return
    for thread in threads:
        console.print(f"- {thread}")


async def _run_repl(settings: Settings, thread_id: str) -> None:
    handler = _make_interrupt_handler(settings)
    console.print(
        Panel(
            f"ADEPT agent — thread [bold]{thread_id}[/]\n{COMMANDS_HELP}",
            border_style="green",
        )
    )
    try:
        async with open_agent_session(settings) as session:
            while True:
                try:
                    user = console.input("[bold green]you >[/] ").strip()
                except (EOFError, KeyboardInterrupt):
                    console.print()
                    break
                if not user:
                    continue
                command = user.lower()
                if command in (":q", ":quit", ":exit"):
                    break
                if command == ":help":
                    console.print(COMMANDS_HELP)
                    continue
                if command == ":threads":
                    _print_threads(settings)
                    continue
                if command == ":new":
                    thread_id = new_thread_id()
                    console.print(f"Started thread [bold]{thread_id}[/]")
                    continue
                if command.startswith(":thread"):
                    parts = user.split(maxsplit=1)
                    if len(parts) == 2:
                        thread_id = parts[1].strip()
                        console.print(f"Switched to thread [bold]{thread_id}[/]")
                    else:
                        console.print("[yellow]Usage: :thread <id>[/]")
                    continue
                override, query = _parse_mention(user, set(_SPECIALIST_NAMES))
                if override is None and user.startswith("@"):
                    # Looks like a routing mention but the name is unknown: warn
                    # and fall back to normal routing rather than dropping the line.
                    candidate = user[1:].split(maxsplit=1)
                    if candidate and candidate[0]:
                        err_console.print(
                            f"[yellow]Unknown specialist '@{escape(candidate[0])}'. "
                            f"Valid: {', '.join(_SPECIALIST_NAMES)}. Routing normally.[/]"
                        )
                elif override is not None and not query:
                    err_console.print(f"[yellow]Add a request after @{override}.[/]")
                    continue
                try:
                    result = await session.run_turn(
                        thread_id,
                        query if override is not None else user,
                        on_interrupt=handler,
                        on_event=_render_progress,
                        route_override=override,
                    )
                except AdeptError as exc:
                    # Expected, typed failures (timeout, config, validation, security)
                    # carry a meaningful message; show it, falling back to the class
                    # name so an empty message never renders as a blank line.
                    err_console.print(f"[red]{escape(str(exc)) or type(exc).__name__}[/]")
                    continue
                except Exception as exc:
                    # Unexpected failures: always name the type (some exceptions, e.g.
                    # the async httpx.ReadTimeout, stringify to an empty message) and
                    # print a traceback so the cause is never hidden.
                    detail = str(exc).strip() or repr(exc)
                    err_console.print(
                        f"[red]Turn failed[/] [dim]({type(exc).__name__})[/]: {escape(detail)}"
                    )
                    err_console.print_exception(show_locals=False)
                    continue
                _print_response(result)
    except Exception as exc:
        err_console.print(f"[red]Could not start agent session:[/] {exc}")
        raise typer.Exit(1) from exc


@app.command()
def chat(
    thread: Annotated[str, typer.Option(help="Resume a named conversation thread.")] = "",
    model: Annotated[str, typer.Option(help="Override the Ollama model for this session.")] = "",
) -> None:
    """Start the interactive detection-engineering chat (persistent history)."""
    settings = get_settings()
    if model:
        settings = settings.model_copy(deep=True)
        settings.agent.model = model
    asyncio.run(_run_repl(settings, thread or new_thread_id()))


@app.command()
def threads() -> None:
    """List saved conversation threads."""
    _print_threads(get_settings())


@app.command()
def audit(
    limit: Annotated[int, typer.Option(help="Number of recent entries to show.")] = 20,
) -> None:
    """Show recent human-approval audit entries."""
    log = AuditLog(get_settings().agent.audit_log)
    entries = log.entries()[-limit:]
    if not entries:
        console.print("[dim]No audit entries yet.[/]")
        return
    for entry in entries:
        console.print(entry)


if __name__ == "__main__":
    app()
