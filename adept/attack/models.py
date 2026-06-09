"""Pydantic models for attack-simulation tools (Atomic Red Team + Caldera).

Atomic Red Team is *propose-only*: ADEPT renders the command, cleanup and the
telemetry a defender should expect, but never runs it. Caldera models normalise
the v2 REST API payloads for the operations the agent may launch behind the
human-approval gate.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AtomicArgument(BaseModel):
    """One input argument of an atomic test."""

    name: str
    description: str = ""
    type: str = "string"
    default: str = ""


class AtomicExecutor(BaseModel):
    """How an atomic test is run (rendered, never executed by ADEPT)."""

    name: str = "manual"
    command: str = ""
    cleanup_command: str = ""
    elevation_required: bool = False
    steps: str = ""


class AtomicTestSummary(BaseModel):
    """A one-line summary of an atomic test for listings."""

    technique: str
    name: str
    guid: str = ""
    supported_platforms: list[str] = Field(default_factory=list)
    executor_name: str = "manual"


class AtomicListing(BaseModel):
    """All atomic tests available for a technique."""

    technique: str
    display_name: str = ""
    total: int = 0
    tests: list[AtomicTestSummary] = Field(default_factory=list)


class AtomicTestPlan(BaseModel):
    """A rendered, propose-only plan for a single atomic test.

    ``command``/``cleanup_command`` have their ``#{arg}`` placeholders resolved
    from ``arguments``. ADEPT does not execute these; a human runs them and the
    defender confirms the expected telemetry fired the detection.
    """

    technique: str
    display_name: str = ""
    name: str
    guid: str = ""
    description: str = ""
    platform: str = ""
    executor_name: str = "manual"
    elevation_required: bool = False
    command: str = ""
    cleanup_command: str = ""
    manual_steps: str = ""
    arguments: dict[str, str] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    note: str = (
        "PROPOSE-ONLY: ADEPT does not run atomics. Review, then execute manually "
        "on an authorised target and confirm the expected telemetry."
    )


class CalderaAdversary(BaseModel):
    """A Caldera adversary profile."""

    adversary_id: str
    name: str = ""
    description: str = ""


class CalderaAgent(BaseModel):
    """A deployed Caldera agent (paw)."""

    paw: str
    host: str = ""
    platform: str = ""
    group: str = ""
    trusted: bool = True


class CalderaOperationSummary(BaseModel):
    """A Caldera operation's high-level state."""

    id: str
    name: str = ""
    state: str = ""
    adversary: str = ""
    start: str = ""


class CalderaOperationReport(BaseModel):
    """A normalised operation report wrapper.

    The raw Caldera report is large and version-specific, so it is preserved
    verbatim under ``report`` while the common fields are surfaced alongside.
    """

    id: str
    name: str = ""
    state: str = ""
    report: dict = Field(default_factory=dict)
