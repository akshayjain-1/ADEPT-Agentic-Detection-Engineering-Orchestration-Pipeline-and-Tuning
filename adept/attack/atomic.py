"""Atomic Red Team support — *propose-only*.

ADEPT never executes atomics. This module loads atomic test definitions from a
local clone of ``redcanaryco/atomic-red-team`` and renders a chosen test (with
``#{arg}`` placeholders resolved) into a command, cleanup command and the
telemetry a defender should expect. A human runs the test on an authorised
target; ADEPT only proposes it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from adept.attack.models import (
    AtomicListing,
    AtomicTestPlan,
    AtomicTestSummary,
)
from adept.shared.errors import (
    BackendNotEnabledError,
    ConfigurationError,
    SecurityError,
    ToolExecutionError,
)

if TYPE_CHECKING:
    from adept.config.settings import AttackSimSettings

_PLACEHOLDER = re.compile(r"#\{([^}]+)\}")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _render(command: str, resolved: dict[str, str]) -> str:
    """Replace ``#{name}`` placeholders with resolved argument values."""

    def _sub(match: re.Match[str]) -> str:
        key = match.group(1)
        return resolved.get(key, match.group(0))

    return _PLACEHOLDER.sub(_sub, command)


@dataclass(slots=True)
class AtomicLibrary:
    """Read-only access to a local Atomic Red Team checkout (propose-only)."""

    settings: AttackSimSettings

    @classmethod
    def from_settings(cls, settings: AttackSimSettings) -> AtomicLibrary:
        return cls(settings=settings)

    # -- guards ------------------------------------------------------------
    def _require_enabled(self) -> None:
        if not self.settings.atomic_enabled:
            raise BackendNotEnabledError(
                "Atomic Red Team is disabled; set ADEPT_ATTACK__ATOMIC_ENABLED=true"
            )

    def _require_allowed(self, technique: str) -> str:
        normalised = technique.strip().upper()
        if not _TECHNIQUE.match(normalised):
            raise ToolExecutionError(
                f"{technique!r} is not a valid ATT&CK technique id (e.g. T1059.001)"
            )
        allowed = {t.strip().upper() for t in self.settings.atomic_allowed_tests}
        if allowed and normalised not in allowed:
            raise SecurityError(
                f"technique {normalised} is not on the Atomic allow-list "
                f"(ADEPT_ATTACK__ATOMIC_ALLOWED_TESTS); refusing to propose it"
            )
        return normalised

    def _atomics_dir(self) -> Path:
        if not self.settings.atomic_path:
            raise ConfigurationError(
                "no Atomic Red Team checkout configured; set ADEPT_ATTACK__ATOMIC_PATH "
                "to a local clone of redcanaryco/atomic-red-team"
            )
        base = Path(self.settings.atomic_path).expanduser()
        nested = base / "atomics"
        return nested if nested.is_dir() else base

    def _load_technique(self, technique: str) -> dict[str, Any]:
        path = self._atomics_dir() / technique / f"{technique}.yaml"
        if not path.is_file():
            raise ToolExecutionError(f"no atomic tests found for {technique} at {path}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ToolExecutionError(f"failed to read atomics for {technique}: {exc}") from exc
        if not isinstance(data, dict):
            raise ToolExecutionError(f"malformed atomic file for {technique}: {path}")
        return data

    # -- public API --------------------------------------------------------
    def list_tests(self, technique: str) -> AtomicListing:
        """List the atomic tests defined for ``technique`` (propose-only)."""
        self._require_enabled()
        normalised = self._require_allowed(technique)
        data = self._load_technique(normalised)
        tests = data.get("atomic_tests") or []
        summaries = [
            AtomicTestSummary(
                technique=normalised,
                name=str(test.get("name", "")),
                guid=str(test.get("auto_generated_guid", "")),
                supported_platforms=[str(p) for p in test.get("supported_platforms", [])],
                executor_name=str((test.get("executor") or {}).get("name", "manual")),
            )
            for test in tests
            if isinstance(test, dict)
        ]
        return AtomicListing(
            technique=normalised,
            display_name=str(data.get("display_name", "")),
            total=len(summaries),
            tests=summaries,
        )

    def plan_test(
        self,
        technique: str,
        *,
        test: str | None = None,
        arguments: dict[str, str] | None = None,
    ) -> AtomicTestPlan:
        """Render a single atomic test into a propose-only plan.

        ``test`` selects the test by 1-based index, name (case-insensitive
        substring) or GUID; the first test is used when omitted. ``arguments``
        overrides input-argument defaults before placeholder substitution.
        """
        self._require_enabled()
        normalised = self._require_allowed(technique)
        data = self._load_technique(normalised)
        raw_tests = [t for t in (data.get("atomic_tests") or []) if isinstance(t, dict)]
        if not raw_tests:
            raise ToolExecutionError(f"no atomic tests defined for {normalised}")

        selected = _select_test(raw_tests, test)
        executor = selected.get("executor") or {}
        defaults = {
            name: str((spec or {}).get("default", ""))
            for name, spec in (selected.get("input_arguments") or {}).items()
        }
        resolved = {**defaults, **(arguments or {})}
        dependencies = [
            str(dep.get("description", "")).strip()
            for dep in (selected.get("dependencies") or [])
            if isinstance(dep, dict)
        ]
        return AtomicTestPlan(
            technique=normalised,
            display_name=str(data.get("display_name", "")),
            name=str(selected.get("name", "")),
            guid=str(selected.get("auto_generated_guid", "")),
            description=str(selected.get("description", "")).strip(),
            platform=",".join(str(p) for p in selected.get("supported_platforms", [])),
            executor_name=str(executor.get("name", "manual")),
            elevation_required=bool(executor.get("elevation_required", False)),
            command=_render(str(executor.get("command", "")), resolved),
            cleanup_command=_render(str(executor.get("cleanup_command", "")), resolved),
            manual_steps=_render(str(executor.get("steps", "")), resolved),
            arguments=resolved,
            dependencies=[dep for dep in dependencies if dep],
        )


def _select_test(tests: list[dict[str, Any]], selector: str | None) -> dict[str, Any]:
    """Pick a test by index (1-based), GUID or name; default to the first."""
    if selector is None or not selector.strip():
        return tests[0]
    needle = selector.strip()
    if needle.isdigit():
        index = int(needle) - 1
        if 0 <= index < len(tests):
            return tests[index]
        raise ToolExecutionError(f"atomic test index {needle} is out of range (1-{len(tests)})")
    lowered = needle.lower()
    for test in tests:
        if str(test.get("auto_generated_guid", "")).lower() == lowered:
            return test
    for test in tests:
        if lowered in str(test.get("name", "")).lower():
            return test
    raise ToolExecutionError(f"no atomic test matching {selector!r}")
