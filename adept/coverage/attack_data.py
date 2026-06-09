"""A read-only catalogue view over the cached ATT&CK STIX bundle.

Provides technique enumeration and lookup for coverage analysis (names, tactics,
platforms, sub-technique flags). The heavy ``mitreattack`` import is deferred to
:meth:`AttackCatalog.from_file`, and analysis code depends only on the small
:class:`CatalogProtocol` so it can be unit-tested with a lightweight fake.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class TechniqueMeta:
    """Static metadata for a single ATT&CK technique."""

    technique_id: str
    name: str
    tactics: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    is_subtechnique: bool = False


class CatalogProtocol(Protocol):
    """The slice of catalogue behaviour the analysis functions require."""

    def name(self, technique_id: str) -> str | None: ...

    def techniques(self) -> list[TechniqueMeta]: ...


def _mitre_external_id(stix_obj: Any) -> str:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id", ""))
    return ""


def _tactics(stix_obj: Any) -> tuple[str, ...]:
    return tuple(
        str(phase.get("phase_name", ""))
        for phase in stix_obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
    )


@dataclass(slots=True)
class AttackCatalog:
    """An in-memory index of enterprise ATT&CK techniques."""

    _by_id: dict[str, TechniqueMeta] = field(default_factory=dict)

    @classmethod
    def from_techniques(cls, metas: Iterable[TechniqueMeta]) -> AttackCatalog:
        """Build a catalogue from pre-parsed technique metadata (test-friendly)."""
        return cls({meta.technique_id: meta for meta in metas})

    @classmethod
    def from_file(cls, stix_filepath: str) -> AttackCatalog:
        """Build a catalogue from an ATT&CK STIX bundle on disk."""
        from mitreattack.stix20 import MitreAttackData

        data = MitreAttackData(stix_filepath)
        metas: dict[str, TechniqueMeta] = {}
        for obj in data.get_techniques(remove_revoked_deprecated=True):
            technique_id = _mitre_external_id(obj)
            if not technique_id:
                continue
            metas[technique_id] = TechniqueMeta(
                technique_id=technique_id,
                name=str(obj.get("name", "")),
                tactics=_tactics(obj),
                platforms=tuple(str(p) for p in (obj.get("x_mitre_platforms") or [])),
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
            )
        return cls(metas)

    def name(self, technique_id: str) -> str | None:
        meta = self._by_id.get(technique_id)
        return meta.name if meta else None

    def get(self, technique_id: str) -> TechniqueMeta | None:
        return self._by_id.get(technique_id)

    def techniques(self) -> list[TechniqueMeta]:
        return list(self._by_id.values())
