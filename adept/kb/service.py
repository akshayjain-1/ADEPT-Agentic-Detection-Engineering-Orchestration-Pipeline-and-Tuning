"""Knowledge-base orchestration: corpus ingestion and retrieval.

Local corpora (own Sigma rules, ATT&CK technique descriptions, the homelab
architecture doc, and rule tuning history) are always available. SigmaHQ
community rules are optional and opt-in: ingested only when a local clone path is
configured, or cloned on demand from a configured remote.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from adept.config.settings import Settings
from adept.kb.embeddings import OllamaEmbedder
from adept.kb.models import IngestReport, KBDocument, KBSearchResult
from adept.kb.sources import (
    iter_attack_documents,
    iter_homelab_documents,
    iter_rule_documents,
    iter_tuning_documents,
)
from adept.kb.store import VectorStore
from adept.shared.errors import ToolExecutionError
from adept.shared.logging import get_logger

if TYPE_CHECKING:
    from adept.intel.service import IntelService

log = get_logger(__name__)

#: All corpora the knowledge base understands, in a sensible ingest order.
ALL_SOURCES: tuple[str, ...] = ("own_rules", "attack", "homelab", "tuning", "sigmahq")


def _rules_subdir(base: Path) -> Path:
    rules = base / "rules"
    return rules if rules.is_dir() else base


@dataclass(slots=True)
class KnowledgeBase:
    """Indexes and queries the detection-engineering knowledge corpus."""

    store: VectorStore
    settings: Settings
    _intel: IntelService | None = field(default=None)

    @classmethod
    def from_settings(
        cls, settings: Settings, *, intel: IntelService | None = None
    ) -> KnowledgeBase:
        embedder = OllamaEmbedder(model=settings.kb.embed_model, host=settings.ollama.base_url)
        store = VectorStore(
            persist_dir=settings.kb.persist_dir,
            collection_name=settings.kb.collection,
            embedder=embedder,
        )
        return cls(store=store, settings=settings, _intel=intel)

    # -- corpus resolution ------------------------------------------------- #
    def _intel_service(self) -> IntelService:
        if self._intel is None:
            from adept.intel.service import IntelService

            self._intel = IntelService.from_settings(self.settings)
        return self._intel

    def _sigmahq_rules_dir(self) -> Path | None:
        kb = self.settings.kb
        if kb.sigmahq_path:
            path = Path(kb.sigmahq_path).expanduser()
            if path.is_dir():
                return _rules_subdir(path)
            log.warning("kb.sigmahq_path_missing", path=str(path))
            return None
        if kb.sigmahq_clone and kb.sigmahq_remote:
            return self._clone_sigmahq()
        return None

    def _clone_sigmahq(self) -> Path | None:
        kb = self.settings.kb
        dest = self.settings.data_dir / "sigmahq"
        if dest.is_dir():
            return _rules_subdir(dest)
        try:
            from git import Repo
        except ImportError as exc:  # pragma: no cover - optional dependency
            log.warning("kb.sigmahq_clone_no_git", error=str(exc))
            return None
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            log.info("kb.sigmahq_cloning", remote=kb.sigmahq_remote, dest=str(dest))
            Repo.clone_from(kb.sigmahq_remote, str(dest), depth=1)
        except Exception as exc:
            log.warning("kb.sigmahq_clone_failed", remote=kb.sigmahq_remote, error=str(exc))
            return None
        return _rules_subdir(dest)

    def _documents_for(self, source: str) -> list[KBDocument] | None:
        """Return documents for a source, or ``None`` if the source is unavailable."""
        if source == "own_rules":
            return list(
                iter_rule_documents(_rules_subdir(self.settings.sigma.path), source="own_rules")
            )
        if source == "homelab":
            doc = self.settings.docs_dir / "homelab_architecture.md"
            if not doc.is_file():
                return None
            return list(
                iter_homelab_documents(
                    doc,
                    chunk_chars=self.settings.kb.chunk_chars,
                    overlap=self.settings.kb.chunk_overlap,
                )
            )
        if source == "tuning":
            metadata_dir = self.settings.sigma.path / "metadata"
            if not metadata_dir.is_dir():
                return None
            return list(iter_tuning_documents(metadata_dir))
        if source == "attack":
            bundle = self._intel_service().attack.ensure_bundle_path()
            return list(iter_attack_documents(bundle))
        if source == "sigmahq":
            rules_dir = self._sigmahq_rules_dir()
            if rules_dir is None:
                return None
            return list(iter_rule_documents(rules_dir, source="sigmahq"))
        raise ToolExecutionError(f"unknown knowledge-base source '{source}'")

    # -- public API -------------------------------------------------------- #
    def ingest(self, sources: Sequence[str] | None = None) -> IngestReport:
        """Index the selected corpora; unknown sources raise, missing ones skip."""
        requested = list(sources) if sources else list(ALL_SOURCES)
        for source in requested:
            if source not in ALL_SOURCES:
                raise ToolExecutionError(
                    f"unknown knowledge-base source '{source}'. "
                    f"Valid sources: {', '.join(ALL_SOURCES)}"
                )
        by_source: dict[str, int] = {}
        skipped: list[str] = []
        for source in requested:
            documents = self._documents_for(source)
            if documents is None:
                skipped.append(source)
                log.info("kb.source_skipped", source=source)
                continue
            indexed = self.store.upsert(documents, batch_size=self.settings.kb.batch_size)
            by_source[source] = indexed
            log.info("kb.source_indexed", source=source, documents=indexed)
        return IngestReport(
            collection=self.settings.kb.collection,
            total_indexed=sum(by_source.values()),
            by_source=by_source,
            skipped_sources=skipped,
            sources=requested,
        )

    def search(
        self,
        query: str,
        *,
        n_results: int | None = None,
        sources: Sequence[str] | None = None,
    ) -> KBSearchResult:
        """Retrieve the most relevant documents for ``query``."""
        limit = n_results or self.settings.kb.max_results
        return self.store.search(query, n_results=limit, sources=sources)

    def count(self) -> int:
        """Return the number of indexed documents."""
        return self.store.count()

    def close(self) -> None:
        """Release any auxiliary resources (the intel HTTP clients)."""
        if self._intel is not None:
            self._intel.close()


def available_sources(settings: Settings) -> Iterator[str]:
    """Yield the sources that currently have data to index."""
    yield "own_rules"
    if (settings.docs_dir / "homelab_architecture.md").is_file():
        yield "homelab"
    if (settings.sigma.path / "metadata").is_dir():
        yield "tuning"
    yield "attack"
    if settings.kb.sigmahq_path or (settings.kb.sigmahq_clone and settings.kb.sigmahq_remote):
        yield "sigmahq"
