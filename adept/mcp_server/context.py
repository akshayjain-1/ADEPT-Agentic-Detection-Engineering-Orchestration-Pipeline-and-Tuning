"""Shared application context for the MCP server.

A single :class:`AppContext` is created at startup and captured by the tool and
resource closures, giving them access to configuration and the Sigma
repository without relying on per-request plumbing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from adept.config.settings import Settings
from adept.intel.service import IntelService
from adept.mcp_server.siem import SiemBackend, build_backends
from adept.mcp_server.sigma_repo import SigmaRepo

if TYPE_CHECKING:
    from adept.attack.service import AttackService
    from adept.coverage.attack_data import AttackCatalog
    from adept.kb.service import KnowledgeBase


@dataclass(slots=True)
class AppContext:
    """Process-wide handles shared by MCP tools and resources."""

    settings: Settings
    sigma_repo: SigmaRepo
    siem_backends: dict[str, SiemBackend]
    intel: IntelService
    _attack_catalog: AttackCatalog | None = None
    _attack: AttackService | None = None
    _knowledge_base: KnowledgeBase | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> AppContext:
        sigma_repo = SigmaRepo(
            settings.sigma.path,
            default_branch=settings.sigma.default_branch,
            protected_branches=settings.sigma.protected_branches,
            remote=settings.sigma.remote or None,
        )
        return cls(
            settings=settings,
            sigma_repo=sigma_repo,
            siem_backends=build_backends(settings),
            intel=IntelService.from_settings(settings),
        )

    def attack_catalog(self) -> AttackCatalog:
        """Return the ATT&CK technique catalogue, built once and cached.

        Reuses the intel client's SSRF-guarded, cached STIX bundle so coverage
        analysis shares the same on-disk data as the threat-intel tools.
        """
        if self._attack_catalog is None:
            from adept.coverage.attack_data import AttackCatalog

            bundle = self.intel.attack.ensure_bundle_path()
            self._attack_catalog = AttackCatalog.from_file(str(bundle))
        return self._attack_catalog

    def knowledge_base(self) -> KnowledgeBase:
        """Return the RAG knowledge base, built once and cached.

        Reuses the shared intel client so ATT&CK ingestion draws on the same
        cached STIX bundle as the threat-intel and coverage tools.
        """
        if self._knowledge_base is None:
            from adept.kb.service import KnowledgeBase

            self._knowledge_base = KnowledgeBase.from_settings(self.settings, intel=self.intel)
        return self._knowledge_base

    def attack(self) -> AttackService:
        """Return the attack-simulation service, built once and cached.

        Bundles the propose-only Atomic Red Team library and the Caldera v2
        client used by the attack tools.
        """
        if self._attack is None:
            from adept.attack.service import AttackService

            self._attack = AttackService.from_settings(self.settings)
        return self._attack
