"""Optional, best-effort DeTT&CT integration (subprocess-only).

DeTT&CT (https://github.com/rabobank-cdc/DeTTECT) is licensed GPL-3.0, so it is
invoked **only** as an external process and is **never imported** — keeping it at
arm's length avoids any license entanglement with ADEPT. The integration is
entirely optional: when DeTT&CT is not enabled or cannot be located, every entry
point degrades gracefully to a ``DettectResult`` with ``available=False`` instead
of raising.

Verified DeTT&CT CLI (v2.x)::

    python dettect.py ds -fd <data-source.yaml> -l   # data-source / visibility layer
    python dettect.py v  -ft <technique.yaml>    -l   # visibility coverage layer
    python dettect.py d  -ft <technique.yaml>    -l   # detection coverage layer

Generated ATT&CK Navigator layer JSON is written to DeTT&CT's ``output/`` folder
(relative to the script). After a run we report any layer files that appeared
there so the caller can pick them up.

Security: commands are always built as argument **lists** (never a shell string),
so there is no shell-injection surface.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from adept.config.settings import CoverageSettings
from adept.shared.logging import get_logger

log = get_logger(__name__)

#: DeTT&CT analysis modes mapped to their YAML administration input flag.
_MODE_INPUT_FLAG = {"ds": "-fd", "v": "-ft", "d": "-ft"}


@dataclass(slots=True)
class DettectResult:
    """Outcome of a DeTT&CT invocation (or a graceful "not available" result)."""

    available: bool
    ok: bool = False
    mode: str = ""
    command: list[str] = field(default_factory=list)
    returncode: int | None = None
    layer_files: list[str] = field(default_factory=list)
    message: str = ""
    stdout_tail: str = ""
    stderr_tail: str = ""


def _resolve_command(settings: CoverageSettings) -> tuple[list[str], Path] | None:
    """Resolve the base command and working directory for DeTT&CT.

    Returns ``(base_argv, cwd)`` or ``None`` when DeTT&CT cannot be located.
    A ``dettect.py`` script path is run with a Python interpreter from its own
    directory (DeTT&CT reads its bundled ``data/`` relative to the script); a
    plain executable name is resolved on ``PATH``.
    """
    command = settings.dettect_command.strip()
    if not command:
        found = shutil.which("dettect")
        if not found:
            return None
        return [found], Path.cwd()

    candidate = Path(command).expanduser()
    if candidate.is_file():
        python = settings.dettect_python.strip() or sys.executable
        return [python, str(candidate)], candidate.resolve().parent

    found = shutil.which(command)
    if found:
        return [found], Path.cwd()
    return None


def is_available(settings: CoverageSettings) -> bool:
    """Return whether DeTT&CT is enabled and locatable."""
    return settings.dettect_enabled and _resolve_command(settings) is not None


def _new_layers(output_dir: Path, since: float) -> list[str]:
    """Return JSON layer files in ``output_dir`` modified at/after ``since``."""
    if not output_dir.is_dir():
        return []
    fresh = [
        path for path in sorted(output_dir.glob("*.json")) if path.stat().st_mtime >= since - 1.0
    ]
    return [str(path) for path in fresh]


def generate_layer(
    settings: CoverageSettings,
    mode: str,
    yaml_path: str | Path,
) -> DettectResult:
    """Run a DeTT&CT layer-generation mode against a YAML administration file.

    ``mode`` is one of ``ds`` (data sources), ``v`` (visibility) or ``d``
    (detection). Always returns a :class:`DettectResult`; it never raises for an
    unavailable tool, a missing input file, or a non-zero exit.
    """
    if mode not in _MODE_INPUT_FLAG:
        return DettectResult(
            available=True,
            mode=mode,
            message=f"unknown DeTT&CT mode '{mode}' (expected one of ds, v, d)",
        )
    if not settings.dettect_enabled:
        return DettectResult(available=False, mode=mode, message="DeTT&CT integration disabled")

    resolved = _resolve_command(settings)
    if resolved is None:
        return DettectResult(
            available=False,
            mode=mode,
            message="DeTT&CT not found (set ADEPT_COVERAGE__DETTECT_COMMAND)",
        )

    yaml_file = Path(yaml_path).expanduser()
    if not yaml_file.is_file():
        return DettectResult(
            available=True,
            mode=mode,
            message=f"DeTT&CT input YAML not found: {yaml_file}",
        )

    base_argv, cwd = resolved
    argv = [*base_argv, mode, _MODE_INPUT_FLAG[mode], str(yaml_file.resolve()), "-l"]
    output_dir = cwd / "output"
    started = time.time()
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, no shell, trusted local tool
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=settings.dettect_timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        return DettectResult(
            available=False, mode=mode, command=argv, message=f"DeTT&CT not executable: {exc}"
        )
    except subprocess.TimeoutExpired:
        log.warning("coverage.dettect.timeout", mode=mode, timeout=settings.dettect_timeout_seconds)
        return DettectResult(
            available=True,
            mode=mode,
            command=argv,
            message=f"DeTT&CT timed out after {settings.dettect_timeout_seconds}s",
        )

    ok = proc.returncode == 0
    layers = _new_layers(output_dir, started) if ok else []
    if not ok:
        log.warning("coverage.dettect.failed", mode=mode, returncode=proc.returncode)
    return DettectResult(
        available=True,
        ok=ok,
        mode=mode,
        command=argv,
        returncode=proc.returncode,
        layer_files=layers,
        message="" if ok else f"DeTT&CT exited with code {proc.returncode}",
        stdout_tail=(proc.stdout or "")[-2000:],
        stderr_tail=(proc.stderr or "")[-2000:],
    )
