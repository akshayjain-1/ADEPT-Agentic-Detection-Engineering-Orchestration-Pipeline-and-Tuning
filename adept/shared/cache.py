"""A small, dependency-free TTL cache persisted to disk.

Used to cache responses from external threat-intel APIs (NVD, CISA KEV,
SigmaHQ, RSS) so the system stays responsive and resilient to rate limits and
transient outages.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any


class DiskCache:
    """A thread-safe, file-backed cache with per-entry time-to-live.

    Values must be JSON-serializable. Each entry is stored as a small JSON file
    named after the SHA-256 of its key.
    """

    def __init__(self, directory: Path, namespace: str = "default") -> None:
        self._dir = Path(directory) / namespace
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self._dir / f"{digest}.json"

    def get(self, key: str) -> Any | None:
        """Return the cached value for ``key`` or ``None`` if missing/expired."""
        path = self._path_for(key)
        with self._lock:
            if not path.exists():
                return None
            try:
                payload = json.loads(path.read_text("utf-8"))
            except (json.JSONDecodeError, OSError):
                return None
            if payload.get("expires_at", 0) < time.time():
                path.unlink(missing_ok=True)
                return None
            return payload.get("value")

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Store ``value`` under ``key`` for ``ttl_seconds`` seconds."""
        path = self._path_for(key)
        payload = {"expires_at": time.time() + ttl_seconds, "value": value}
        with self._lock:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), "utf-8")
            tmp.replace(path)

    def clear(self) -> None:
        """Remove all entries in this cache namespace."""
        with self._lock:
            for entry in self._dir.glob("*.json"):
                entry.unlink(missing_ok=True)
