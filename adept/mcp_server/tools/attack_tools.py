"""Attack-simulation tools exposed over MCP.

These back the Purple-Team Operator agent. Atomic Red Team tools are
*propose-only* (ADEPT renders the command, cleanup and expected telemetry but
never runs it) and are therefore safe to call. The Caldera read tools inspect a
running server; ``run_caldera_operation`` and ``stop_caldera_operation`` change
state and are listed in ``agent.dangerous_tools`` so the agent routes them
through its human-approval gate before they execute.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from adept.mcp_server.context import AppContext
from adept.mcp_server.tools._annotations import DESTRUCTIVE, READ_ONLY
from adept.shared.errors import AdeptError

_STOP_STATES = {"running", "paused", "finished", "cleanup", "run_one_link"}


def register_attack_tools(mcp: FastMCP, ctx: AppContext) -> None:
    """Register the attack-simulation tools on the server."""

    @mcp.tool(title="List Atomic Red Team tests", annotations=READ_ONLY)
    def list_atomic_tests(technique: str) -> dict[str, object]:
        """List the Atomic Red Team tests defined for an ATT&CK technique.

        ``technique`` is an ATT&CK id such as ``T1059.001``. Requires a local
        atomic-red-team checkout and the technique to be on the configured
        allow-list. Propose-only: nothing is executed.
        """
        try:
            return ctx.attack().atomic.list_tests(technique).model_dump()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Plan an Atomic Red Team test", annotations=READ_ONLY)
    def plan_atomic_test(
        technique: str,
        test: str | None = None,
        arguments: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """Render a propose-only plan for one atomic test.

        ``test`` selects by 1-based index, name (case-insensitive substring) or
        GUID (defaults to the first test). ``arguments`` overrides input-argument
        defaults before ``#{...}`` placeholders are substituted. Returns the
        command, cleanup command, elevation requirement and a run-manually note;
        ADEPT never executes the test.
        """
        try:
            return (
                ctx.attack()
                .atomic.plan_test(technique, test=test, arguments=arguments)
                .model_dump()
            )
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="List Caldera adversaries", annotations=READ_ONLY)
    def list_caldera_adversaries() -> dict[str, object]:
        """List the adversary profiles available on the Caldera server."""
        try:
            adversaries = ctx.attack().caldera.list_adversaries()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return {"adversaries": [item.model_dump() for item in adversaries]}

    @mcp.tool(title="List Caldera agents", annotations=READ_ONLY)
    def list_caldera_agents() -> dict[str, object]:
        """List the deployed Caldera agents (paws) and their host/group."""
        try:
            agents = ctx.attack().caldera.list_agents()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return {"agents": [item.model_dump() for item in agents]}

    @mcp.tool(title="List Caldera operations", annotations=READ_ONLY)
    def list_caldera_operations() -> dict[str, object]:
        """List the operations on the Caldera server with their current state."""
        try:
            operations = ctx.attack().caldera.list_operations()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
        return {"operations": [item.model_dump() for item in operations]}

    @mcp.tool(title="Get a Caldera operation report", annotations=READ_ONLY)
    def get_caldera_operation_report(
        operation_id: str, agent_output: bool = False
    ) -> dict[str, object]:
        """Fetch the full report for a Caldera operation.

        Set ``agent_output`` to include raw command output (can be large). Used
        to observe which abilities ran so detections can be scored.
        """
        try:
            return (
                ctx.attack()
                .caldera.get_operation_report(operation_id, agent_output=agent_output)
                .model_dump()
            )
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Launch a Caldera operation", annotations=DESTRUCTIVE)
    def run_caldera_operation(
        name: str,
        adversary_id: str,
        group: str | None = None,
    ) -> dict[str, object]:
        """Launch a Caldera adversary-emulation operation.

        DANGEROUS: this starts live adversary emulation against the agents in
        ``group``. The agent routes it through the human-approval gate first.
        Returns the created operation's id and state.
        """
        try:
            return (
                ctx.attack().caldera.create_operation(name, adversary_id, group=group).model_dump()
            )
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(title="Stop a Caldera operation", annotations=DESTRUCTIVE)
    def stop_caldera_operation(operation_id: str, state: str = "finished") -> dict[str, object]:
        """Change a Caldera operation's state (default ``finished`` to stop it).

        DANGEROUS: altering a running operation is gated by human approval.
        ``state`` must be one of running, paused, finished, cleanup,
        run_one_link.
        """
        if state not in _STOP_STATES:
            raise ToolError(
                f"invalid operation state {state!r}; expected one of {sorted(_STOP_STATES)}"
            )
        try:
            return ctx.attack().caldera.set_operation_state(operation_id, state).model_dump()
        except AdeptError as exc:
            raise ToolError(str(exc)) from exc
