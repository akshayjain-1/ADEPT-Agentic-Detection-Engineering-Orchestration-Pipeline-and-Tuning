"""Append-only audit trail for human-in-the-loop approval decisions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AuditLog:
    """A simple append-only JSONL audit log.

    Each call to :meth:`record` appends one JSON object (with a UTC timestamp)
    on its own line. The log is intended to be immutable: entries are only ever
    appended, never rewritten.
    """

    path: Path

    def record(self, event: str, **data: Any) -> dict[str, Any]:
        """Append a timestamped ``event`` with ``data`` and return the entry."""
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            **data,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
        return entry

    def entries(self) -> list[dict[str, Any]]:
        """Return all recorded entries (empty if the log file does not exist)."""
        if not self.path.is_file():
            return []
        records: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
        return records
