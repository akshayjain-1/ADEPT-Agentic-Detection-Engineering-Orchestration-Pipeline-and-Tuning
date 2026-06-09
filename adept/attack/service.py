"""Attack-simulation service: Atomic Red Team (propose-only) + Caldera.

Bundles the read/render Atomic library and the Caldera v2 client behind one
handle so the MCP layer can build everything from configuration in one call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from adept.attack.atomic import AtomicLibrary
from adept.attack.caldera import CalderaClient

if TYPE_CHECKING:
    from adept.config.settings import Settings


@dataclass(slots=True)
class AttackService:
    """Combined Atomic + Caldera attack-simulation backends."""

    atomic: AtomicLibrary
    caldera: CalderaClient

    @classmethod
    def from_settings(cls, settings: Settings) -> AttackService:
        return cls(
            atomic=AtomicLibrary.from_settings(settings.attack),
            caldera=CalderaClient.from_settings(settings.attack),
        )

    def close(self) -> None:
        self.caldera.close()
