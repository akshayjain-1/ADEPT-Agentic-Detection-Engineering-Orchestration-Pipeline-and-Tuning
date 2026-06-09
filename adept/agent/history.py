"""SQLite-backed conversation thread helpers for the agent CLI."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


def list_threads(db_path: Path) -> list[str]:
    """Return the distinct conversation thread ids stored in the checkpoint DB.

    The database is opened read-only; a missing file or an un-initialised schema
    yields an empty list rather than an error.
    """
    if not db_path.is_file():
        return []
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        exists = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='checkpoints'"
        ).fetchone()
        if exists is None:
            return []
        rows = connection.execute(
            "SELECT DISTINCT thread_id FROM checkpoints ORDER BY thread_id"
        ).fetchall()
        return [str(row[0]) for row in rows]
    finally:
        connection.close()


def new_thread_id() -> str:
    """Generate a fresh, human-readable thread id."""
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{uuid4().hex[:6]}"
