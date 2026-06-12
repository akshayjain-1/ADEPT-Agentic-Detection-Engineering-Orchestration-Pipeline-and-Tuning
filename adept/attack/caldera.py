"""MITRE Caldera v2 REST client.

Wraps the subset of the Caldera v2 API ADEPT needs to inspect and (behind the
human-approval gate) launch adversary-emulation operations. Authentication uses
the ``KEY`` header with the configured red API key. State-changing calls
(create/stop) are exposed as *dangerous* MCP tools so they pass through the
agent's approval gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from adept.attack.models import (
    CalderaAdversary,
    CalderaAgent,
    CalderaOperationReport,
    CalderaOperationSummary,
)
from adept.shared.errors import (
    BackendNotEnabledError,
    ConfigurationError,
    SecurityError,
    ToolExecutionError,
)

if TYPE_CHECKING:
    from adept.config.settings import AttackSimSettings

_ALLOWED_SCHEMES = {"http", "https"}


@dataclass(slots=True)
class CalderaClient:
    """A small, typed client for the Caldera v2 REST API."""

    base_url: str
    api_key: str
    enabled: bool
    header_name: str = "KEY"
    planner_id: str = "atomic"
    source_id: str = "basic"
    default_group: str = ""
    timeout: float = 30.0
    _client: httpx.Client | None = field(default=None, repr=False)

    @classmethod
    def from_settings(cls, settings: AttackSimSettings) -> CalderaClient:
        base = settings.caldera_url.rstrip("/")
        return cls(
            base_url=f"{base}/api/v2" if base else "",
            api_key=settings.caldera_api_key.get_secret_value(),
            enabled=settings.caldera_enabled,
            header_name=settings.caldera_api_key_header or "KEY",
            planner_id=settings.caldera_planner_id,
            source_id=settings.caldera_source_id,
            default_group=settings.caldera_default_group,
            timeout=float(settings.caldera_timeout_seconds),
        )

    # -- guards ------------------------------------------------------------
    def _require_ready(self) -> None:
        if not self.enabled:
            raise BackendNotEnabledError(
                "Caldera is disabled; set ADEPT_ATTACK__CALDERA_ENABLED=true"
            )
        if not self.base_url:
            raise ConfigurationError("no Caldera server configured; set ADEPT_ATTACK__CALDERA_URL")
        if urlsplit(self.base_url).scheme not in _ALLOWED_SCHEMES:
            raise SecurityError(f"refusing to call Caldera over a non-HTTP(S) URL: {self.base_url}")

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                headers={self.header_name: self.api_key},
            )
        return self._client

    def _request(self, method: str, path: str, *, json: Any = None) -> Any:
        self._require_ready()
        url = f"{self.base_url}{path}"
        try:
            response = self._http().request(method, url, json=json)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ToolExecutionError(f"Caldera request {method} {path} failed: {exc}") from exc
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise ToolExecutionError(f"Caldera response for {path} was not JSON: {exc}") from exc

    # -- read --------------------------------------------------------------
    def list_adversaries(self) -> list[CalderaAdversary]:
        data = self._request("GET", "/adversaries") or []
        return [
            CalderaAdversary(
                adversary_id=str(item.get("adversary_id", "")),
                name=str(item.get("name", "")),
                description=str(item.get("description", "")),
            )
            for item in data
            if isinstance(item, dict)
        ]

    def list_agents(self) -> list[CalderaAgent]:
        data = self._request("GET", "/agents") or []
        return [
            CalderaAgent(
                paw=str(item.get("paw", "")),
                host=str(item.get("host", "")),
                platform=str(item.get("platform", "")),
                group=str(item.get("group", "")),
                trusted=bool(item.get("trusted", True)),
            )
            for item in data
            if isinstance(item, dict)
        ]

    def list_operations(self) -> list[CalderaOperationSummary]:
        data = self._request("GET", "/operations") or []
        return [_operation_summary(item) for item in data if isinstance(item, dict)]

    def get_operation_report(
        self, operation_id: str, *, agent_output: bool = False
    ) -> CalderaOperationReport:
        data = self._request(
            "POST",
            f"/operations/{operation_id}/report",
            json={"enable_agent_output": agent_output},
        )
        report = data if isinstance(data, dict) else {}
        return CalderaOperationReport(
            id=str(report.get("id", operation_id)),
            name=str(report.get("name", "")),
            state=str(report.get("state", "")),
            report=report,
        )

    # -- write (dangerous; gated by the agent's approval step) -------------
    def create_operation(
        self,
        name: str,
        adversary_id: str,
        *,
        group: str | None = None,
        planner_id: str | None = None,
        source_id: str | None = None,
    ) -> CalderaOperationSummary:
        body = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "planner": {"id": planner_id or self.planner_id},
            "source": {"id": source_id or self.source_id},
            "group": self.default_group if group is None else group,
        }
        data = self._request("POST", "/operations", json=body)
        return _operation_summary(data if isinstance(data, dict) else {})

    def set_operation_state(self, operation_id: str, state: str) -> CalderaOperationSummary:
        data = self._request("PATCH", f"/operations/{operation_id}", json={"state": state})
        return _operation_summary(data if isinstance(data, dict) else {})

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


def _operation_summary(item: dict[str, Any]) -> CalderaOperationSummary:
    adversary = item.get("adversary")
    adversary_name = adversary.get("name", "") if isinstance(adversary, dict) else ""
    return CalderaOperationSummary(
        id=str(item.get("id", "")),
        name=str(item.get("name", "")),
        state=str(item.get("state", "")),
        adversary=str(adversary_name),
        start=str(item.get("start", "")),
    )
