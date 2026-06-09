"""Chroma-backed vector store for the knowledge base.

Embeddings are computed explicitly by the configured :class:`Embedder` and passed
to Chroma directly, so the collection is created with ``embedding_function=None``
and Chroma never tries to download its default model. The Chroma client is built
lazily on first use.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adept.kb.embeddings import Embedder
from adept.kb.models import KBDocument, KBSearchHit, KBSearchResult
from adept.shared.errors import ToolExecutionError
from adept.shared.logging import get_logger

log = get_logger(__name__)


def _flatten_metadata(doc: KBDocument) -> dict[str, str]:
    """Build a flat string-only metadata mapping Chroma can store."""
    meta = {"source": doc.source, "title": doc.title}
    for key, value in doc.metadata.items():
        meta[key] = str(value)
    return meta


def _first(rows: Any) -> list[Any]:
    """Return the first per-query row from a Chroma result list-of-lists."""
    if not rows:
        return []
    first = rows[0]
    return list(first) if first else []


@dataclass(slots=True)
class VectorStore:
    """A persistent Chroma collection addressed by externally-supplied vectors."""

    persist_dir: Path
    collection_name: str
    embedder: Embedder
    _client: Any = field(default=None)
    _collection: Any = field(default=None)

    def _get_collection(self) -> Any:
        if self._collection is None:
            try:
                import chromadb

                Path(self.persist_dir).mkdir(parents=True, exist_ok=True)
                self._client = chromadb.PersistentClient(path=str(self.persist_dir))
                self._collection = self._client.get_or_create_collection(
                    name=self.collection_name,
                    embedding_function=None,
                    metadata={"hnsw:space": "cosine"},
                )
            except Exception as exc:
                raise ToolExecutionError(
                    f"Failed to open vector collection '{self.collection_name}': {exc}"
                ) from exc
        return self._collection

    def upsert(self, documents: Sequence[KBDocument], *, batch_size: int = 64) -> int:
        """Embed and upsert documents; re-indexing the same id is idempotent."""
        docs = [d for d in documents if d.text.strip()]
        if not docs:
            return 0
        collection = self._get_collection()
        step = max(1, batch_size)
        total = 0
        for start in range(0, len(docs), step):
            batch = docs[start : start + step]
            embeddings = self.embedder.embed_documents([d.text for d in batch])
            try:
                collection.upsert(
                    ids=[d.id for d in batch],
                    documents=[d.text for d in batch],
                    embeddings=embeddings,
                    metadatas=[_flatten_metadata(d) for d in batch],
                )
            except Exception as exc:
                raise ToolExecutionError(f"Vector upsert failed: {exc}") from exc
            total += len(batch)
        return total

    def search(
        self,
        query: str,
        *,
        n_results: int = 5,
        sources: Sequence[str] | None = None,
    ) -> KBSearchResult:
        """Embed ``query`` and return the closest documents, newest filter wins."""
        collection = self._get_collection()
        embedding = self.embedder.embed_query(query)
        where: dict[str, Any] | None = None
        if sources:
            selected = list(sources)
            where = {"source": selected[0]} if len(selected) == 1 else {"source": {"$in": selected}}
        try:
            result = collection.query(
                query_embeddings=[embedding],
                n_results=max(1, n_results),
                where=where,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:
            raise ToolExecutionError(f"Vector query failed: {exc}") from exc
        return _build_result(query, result)

    def count(self) -> int:
        """Return the number of indexed documents."""
        return int(self._get_collection().count())


def _build_result(query: str, result: Any) -> KBSearchResult:
    ids = _first(result.get("ids"))
    documents = _first(result.get("documents"))
    metadatas = _first(result.get("metadatas"))
    distances = _first(result.get("distances"))
    hits: list[KBSearchHit] = []
    for index, doc_id in enumerate(ids):
        meta = dict(metadatas[index]) if index < len(metadatas) and metadatas[index] else {}
        distance = float(distances[index]) if index < len(distances) else 1.0
        text = documents[index] if index < len(documents) else ""
        source = str(meta.pop("source", ""))
        title = str(meta.pop("title", ""))
        hits.append(
            KBSearchHit(
                id=str(doc_id),
                source=source,
                title=title,
                score=round(1.0 - distance, 4),
                text=str(text),
                metadata={key: str(value) for key, value in meta.items()},
            )
        )
    return KBSearchResult(query=query, total=len(hits), hits=hits)
