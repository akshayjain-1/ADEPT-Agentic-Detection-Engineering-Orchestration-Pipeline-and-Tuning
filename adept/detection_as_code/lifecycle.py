"""Rule lifecycle metadata: load and validate the ``*.meta.yml`` sidecars.

Each Sigma rule has an operational metadata sidecar under ``metadata/`` that
mirrors the ``rules/`` tree. This module loads a sidecar, validates it against
``lifecycle.schema.json`` (the single source of truth for the schema), and
exposes a typed view plus the allowed stage transitions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator

from adept.detection_as_code.models import LifecycleStage
from adept.shared.errors import ConfigurationError, ValidationFailedError

#: Allowed lifecycle stage transitions (forward through the lifecycle, with
#: disable/deprecate reachable from active stages and re-activation from
#: disabled). Used to guard programmatic stage changes.
STAGE_TRANSITIONS: dict[LifecycleStage, set[LifecycleStage]] = {
    "draft": {"testing", "disabled", "deprecated"},
    "testing": {"production", "draft", "disabled", "deprecated"},
    "production": {"disabled", "deprecated", "testing"},
    "disabled": {"testing", "production", "deprecated"},
    "deprecated": set(),
}


def _normalise(obj: Any) -> Any:
    """Coerce YAML-native dates/datetimes to ISO strings for JSON Schema."""
    return json.loads(json.dumps(obj, default=str))


def schema_path(repo_root: Path) -> Path:
    return repo_root / "metadata" / "lifecycle.schema.json"


def load_metadata(meta_path: Path, repo_root: Path) -> dict[str, Any]:
    """Load and schema-validate a single metadata sidecar.

    Raises :class:`ValidationFailedError` on any schema violation and
    :class:`ConfigurationError` when files are missing or malformed.
    """
    schema_file = schema_path(repo_root)
    if not schema_file.is_file():
        raise ConfigurationError(f"lifecycle schema not found at {schema_file}")
    schema = json.loads(schema_file.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)

    try:
        raw = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{meta_path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError(f"{meta_path}: metadata must be a mapping")

    meta = _normalise(raw)
    errors = sorted(validator.iter_errors(meta), key=str)
    if errors:
        details = "; ".join(
            f"{'/'.join(str(p) for p in err.path) or '<root>'}: {err.message}" for err in errors
        )
        raise ValidationFailedError(f"{meta_path}: metadata invalid: {details}")
    return meta


def can_transition(current: LifecycleStage, target: LifecycleStage) -> bool:
    """Return whether moving a rule from ``current`` to ``target`` is allowed."""
    return target in STAGE_TRANSITIONS.get(current, set())
