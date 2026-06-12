"""Outbound notifications for approval requests and deployment events.

Supports a few simple, self-hostable backends. All are optional; the default
``none`` backend silently does nothing so the rest of the system is unaffected.
"""

from __future__ import annotations

from typing import Literal

import httpx

from adept.config.settings import NotifySettings
from adept.shared.logging import get_logger

log = get_logger(__name__)

Level = Literal["info", "warning", "critical"]


class Notifier:
    """Send short notifications to a configured backend."""

    def __init__(self, settings: NotifySettings) -> None:
        self._settings = settings

    async def send(self, title: str, message: str, level: Level = "info") -> bool:
        """Send a notification. Returns ``True`` on success (or when disabled).

        Never raises on delivery failure: notifications are best-effort and
        must not break a detection workflow.
        """
        backend = self._settings.backend
        if backend == "none":
            return True
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await self._dispatch(client, backend, title, message, level)
            return True
        except Exception as exc:  # best-effort: a delivery failure must not break a workflow
            log.warning("notification_failed", backend=backend, error=str(exc))
            return False

    async def _dispatch(
        self,
        client: httpx.AsyncClient,
        backend: str,
        title: str,
        message: str,
        level: Level,
    ) -> None:
        if backend == "ntfy":
            headers = {"Title": title, "Priority": _ntfy_priority(level)}
            if self._settings.token:
                headers["Authorization"] = f"Bearer {self._settings.token.get_secret_value()}"
            url = self._settings.url.rstrip("/")
            if self._settings.topic:
                url = f"{url}/{self._settings.topic}"
            resp = await client.post(url, content=message.encode("utf-8"), headers=headers)
            resp.raise_for_status()
        elif backend == "discord":
            resp = await client.post(
                self._settings.url, json={"content": f"**{title}**\n{message}"}
            )
            resp.raise_for_status()
        elif backend == "slack":
            resp = await client.post(self._settings.url, json={"text": f"*{title}*\n{message}"})
            resp.raise_for_status()
        elif backend == "webhook":
            headers = {}
            if self._settings.token:
                headers["Authorization"] = f"Bearer {self._settings.token.get_secret_value()}"
            resp = await client.post(
                self._settings.url,
                json={"title": title, "message": message, "level": level},
                headers=headers,
            )
            resp.raise_for_status()


def _ntfy_priority(level: Level) -> str:
    return {"info": "default", "warning": "high", "critical": "urgent"}[level]
