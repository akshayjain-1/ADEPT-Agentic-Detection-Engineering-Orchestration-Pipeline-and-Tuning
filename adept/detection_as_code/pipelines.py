"""Pipeline selection and loading for Sigma conversion.

pySigma "processing pipelines" translate generic Sigma field names into the
field schema of a particular log source / SIEM (e.g. ECS for Elasticsearch,
CIM for Splunk). The right pipeline depends on both the SIEM and the rule's
log source ``product``.

The default policy here is intentionally small and transparent (the homelab is
Windows/Sysmon centric). Callers may override it with explicit pipeline names;
pipeline *file* paths are only loaded from an explicitly allowed directory so a
model-supplied spec cannot read arbitrary files (see ``build_pipeline``).
"""

from __future__ import annotations

from functools import reduce
from pathlib import Path

from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.pipeline import ProcessingPipeline

from adept.shared.errors import ConfigurationError, SecurityError

#: (siem_id, product) -> ordered list of built-in pipeline names.
#: ``sysmon`` normalises Sysmon event fields; the second pipeline maps to the
#: SIEM's field schema. Verified against pySigma's installed pipelines.
_WINDOWS_PIPELINES: dict[str, list[str]] = {
    "elk": ["sysmon", "ecs_windows"],
    "opensearch": ["sysmon", "ecs_windows"],
    "splunk": ["sysmon", "splunk_windows"],
}


def default_pipelines(siem_id: str, product: str | None) -> list[str]:
    """Return the default pipeline names for a SIEM id and log-source product.

    Windows rules get the Sysmon + SIEM-schema pipelines. For other products no
    default pipeline is applied (the rule is converted with its native field
    names); callers can override by passing explicit pipelines to the converter.
    """
    if product == "windows":
        return list(_WINDOWS_PIPELINES.get(siem_id, []))
    return []


def _resolve_pipeline_path(spec: str, allowed_dir: Path) -> Path:
    """Resolve a pipeline file ``spec`` and confine it to ``allowed_dir``.

    Pipeline specs may originate from the model, so an unconstrained path would
    be an arbitrary-file-read primitive. The resolved path must stay inside
    ``allowed_dir`` and name an existing ``.yml``/``.yaml`` file.
    """
    base = allowed_dir.resolve()
    candidate = Path(spec)
    resolved = (candidate if candidate.is_absolute() else base / candidate).resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise SecurityError(
            f"pipeline path {spec!r} resolves outside the allowed directory {base}"
        ) from exc
    if resolved.suffix.lower() not in {".yml", ".yaml"}:
        raise ConfigurationError(f"pipeline file must be a .yml/.yaml file: {spec!r}")
    if not resolved.is_file():
        raise ConfigurationError(f"pipeline file not found: {spec!r}")
    return resolved


def _load_one(
    spec: str, plugins: InstalledSigmaPlugins, allowed_dir: Path | None
) -> ProcessingPipeline:
    """Resolve a single pipeline spec.

    An installed pipeline *name* is always accepted. A filesystem path is only
    honoured when ``allowed_dir`` is set and the path resolves inside it;
    otherwise the spec is rejected without ever touching the filesystem.
    """
    factory = plugins.pipelines.get(spec)
    if factory is not None:
        pipeline = factory()
        if not isinstance(pipeline, ProcessingPipeline):  # pragma: no cover - defensive
            raise ConfigurationError(f"pipeline {spec!r} did not produce a ProcessingPipeline")
        return pipeline
    if allowed_dir is None:
        raise ConfigurationError(
            f"unknown pipeline {spec!r}: not an installed pipeline name "
            "(pipeline file paths are not accepted in this context)"
        )
    path = _resolve_pipeline_path(spec, allowed_dir)
    return ProcessingPipeline.from_yaml(path.read_text(encoding="utf-8"))


def build_pipeline(
    specs: list[str],
    plugins: InstalledSigmaPlugins | None = None,
    *,
    allowed_dir: Path | None = None,
) -> ProcessingPipeline | None:
    """Combine pipeline specs into a single :class:`ProcessingPipeline`.

    Returns ``None`` when ``specs`` is empty (convert with native field names).

    ``specs`` may name installed pipelines. Filesystem paths are loaded only
    when ``allowed_dir`` is provided and the resolved path stays within it,
    keeping model-supplied specs from reading arbitrary files.
    """
    if not specs:
        return None
    plugins = plugins or InstalledSigmaPlugins.autodiscover()
    pipelines = [_load_one(spec, plugins, allowed_dir) for spec in specs]
    return reduce(lambda a, b: a + b, pipelines)
