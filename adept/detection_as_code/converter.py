"""Sigma-to-SIEM rule conversion using pySigma.

Wraps the verified pySigma Python API: discover installed backends/pipelines,
build a (optionally combined) processing pipeline for the target SIEM and log
source, and convert a Sigma rule into the SIEM's query language.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.plugins import InstalledSigmaPlugins

from adept.detection_as_code.models import ConversionResult
from adept.detection_as_code.pipelines import build_pipeline, default_pipelines
from adept.detection_as_code.targets import (
    SIEM_CONVERTER_TARGETS,
    SIEM_QUERY_LANGUAGE,
)
from adept.shared.errors import ConfigurationError, ValidationFailedError


def _first_product(collection: SigmaCollection) -> str | None:
    for rule in collection.rules:
        logsource = getattr(rule, "logsource", None)
        product = getattr(logsource, "product", None) if logsource is not None else None
        if product:
            return str(product)
    return None


class SigmaConverter:
    """Convert Sigma rules to ELK/OpenSearch/Splunk query languages."""

    def __init__(self, *, pipeline_dir: Path | None = None) -> None:
        """Create a converter.

        ``pipeline_dir`` confines pipeline *file* specs to a single directory.
        Leave it ``None`` (the default) to accept only installed pipeline
        names — the safe choice when pipeline specs may originate from the model.
        """
        self._pipeline_dir = pipeline_dir

    @cached_property
    def _plugins(self) -> InstalledSigmaPlugins:
        # ``autodiscover`` is moderately expensive; cache it on the instance.
        return InstalledSigmaPlugins.autodiscover()

    @staticmethod
    def _parse(rule_text: str) -> SigmaCollection:
        try:
            return SigmaCollection.from_yaml(rule_text)
        except (SigmaError, yaml.YAMLError) as exc:
            raise ValidationFailedError(f"Sigma rule failed to parse: {exc}") from exc

    def convert(
        self,
        rule_text: str,
        siem_id: str,
        *,
        pipelines: list[str] | None = None,
    ) -> ConversionResult:
        """Convert a Sigma rule (YAML text) into queries for ``siem_id``.

        ``pipelines`` overrides the default pipeline policy when provided.
        """
        target = SIEM_CONVERTER_TARGETS.get(siem_id)
        if target is None:
            raise ConfigurationError(
                f"unknown SIEM id {siem_id!r}; expected one of {sorted(SIEM_CONVERTER_TARGETS)}"
            )
        # pySigma annotates ``backends`` values as instances, but at runtime
        # they are backend *classes*; treat as Any to construct them.
        backend_cls: Any = self._plugins.backends.get(target)
        if backend_cls is None:  # pragma: no cover - defensive
            raise ConfigurationError(f"pySigma backend for target {target!r} is not installed")

        collection = self._parse(rule_text)
        specs = (
            pipelines
            if pipelines is not None
            else default_pipelines(siem_id, _first_product(collection))
        )
        pipeline = build_pipeline(specs, self._plugins, allowed_dir=self._pipeline_dir)
        backend = backend_cls(processing_pipeline=pipeline)
        try:
            queries = backend.convert(collection)
        except SigmaError as exc:
            raise ValidationFailedError(f"conversion to {target} failed: {exc}") from exc

        return ConversionResult(
            siem=siem_id,
            target=target,
            query_language=SIEM_QUERY_LANGUAGE.get(siem_id, target),
            pipelines=specs,
            queries=[str(query) for query in queries],
        )
