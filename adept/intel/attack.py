"""MITRE ATT&CK (enterprise) technique lookup.

Downloads the official ATT&CK STIX bundle once (allowlist-guarded), caches it to
disk, and uses ``mitreattack-python`` to resolve a technique by its ATT&CK id
(e.g. ``T1003`` or ``T1003.001``). The heavy ``mitreattack`` import is deferred
to first use so the module stays light and importable without the intel extra.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from adept.intel.http import IntelHTTP
from adept.intel.models import AttackTechnique
from adept.shared.errors import ValidationFailedError

if TYPE_CHECKING:
    from mitreattack.stix20 import MitreAttackData

_ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def validate_attack_id(attack_id: str) -> str:
    """Return the normalised ATT&CK technique id or raise if malformed."""
    candidate = attack_id.strip().upper()
    if not _ATTACK_ID_RE.match(candidate):
        raise ValidationFailedError(
            f"invalid ATT&CK technique id: {attack_id!r} (expected T#### or T####.###)"
        )
    return candidate


def _mitre_url(stix_obj: Any) -> tuple[str, str]:
    """Return ``(external_id, url)`` from a STIX object's ATT&CK reference."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id", "")), str(ref.get("url", ""))
    return "", ""


def parse_technique(stix_obj: Any, tactics: list[str]) -> AttackTechnique:
    """Normalise a STIX ``attack-pattern`` object into an :class:`AttackTechnique`."""
    external_id, url = _mitre_url(stix_obj)
    return AttackTechnique(
        attack_id=external_id,
        name=str(stix_obj.get("name", "")),
        description=str(stix_obj.get("description", "")),
        is_subtechnique=bool(stix_obj.get("x_mitre_is_subtechnique", False)),
        tactics=tactics,
        platforms=list(stix_obj.get("x_mitre_platforms", []) or []),
        data_sources=list(stix_obj.get("x_mitre_data_sources", []) or []),
        detection=str(stix_obj.get("x_mitre_detection", "") or ""),
        url=url,
    )


class AttackClient:
    """Resolve ATT&CK techniques from the cached STIX bundle."""

    def __init__(
        self,
        http: IntelHTTP,
        *,
        stix_url: str,
        cache_file: Path,
        ttl_seconds: int,
    ) -> None:
        self._http = http
        self._stix_url = stix_url
        self._cache_file = Path(cache_file)
        self._ttl = ttl_seconds
        self._data: MitreAttackData | None = None

    def _bundle_is_fresh(self) -> bool:
        if not self._cache_file.is_file():
            return False
        age = time.time() - self._cache_file.stat().st_mtime
        return age < self._ttl

    def _ensure_bundle(self) -> None:
        if self._bundle_is_fresh():
            return
        text = self._http.download_text(self._stix_url)
        self._cache_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._cache_file.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(self._cache_file)
        self._data = None  # force rebuild against the refreshed bundle

    def _attack_data(self) -> MitreAttackData:
        if self._data is None:
            from mitreattack.stix20 import MitreAttackData

            self._ensure_bundle()
            self._data = MitreAttackData(str(self._cache_file))
        return self._data

    def ensure_bundle_path(self) -> Path:
        """Download/refresh the STIX bundle if needed and return its path.

        Lets other components (e.g. coverage analysis) build their own view over
        the same cached bundle without re-implementing the SSRF-guarded download.
        """
        self._ensure_bundle()
        return self._cache_file

    def get_technique(self, attack_id: str) -> AttackTechnique:
        """Look up an ATT&CK enterprise technique by id."""
        normalised = validate_attack_id(attack_id)
        data = self._attack_data()
        stix_obj = data.get_object_by_attack_id(normalised, "attack-pattern")
        if stix_obj is None:
            raise ValidationFailedError(f"no ATT&CK technique found for {normalised}")
        tactic_objs = data.get_tactics_by_technique(stix_obj["id"])
        tactics = [str(t.get("name", "")) for t in tactic_objs if t.get("name")]
        return parse_technique(stix_obj, tactics)
