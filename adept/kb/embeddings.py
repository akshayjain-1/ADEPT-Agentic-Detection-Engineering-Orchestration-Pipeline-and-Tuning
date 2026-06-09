"""Embedding backends for the knowledge base.

The :class:`Embedder` protocol decouples the vector store from any particular
embedding provider so it can be unit-tested with a deterministic fake. The
production implementation calls a local Ollama server lazily, so importing this
module (and building the MCP server) never requires Ollama to be running.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from adept.shared.errors import ToolExecutionError
from adept.shared.logging import get_logger

log = get_logger(__name__)


@runtime_checkable
class Embedder(Protocol):
    """Turns text into embedding vectors."""

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        """Embed a batch of documents, preserving order."""
        ...

    def embed_query(self, text: str) -> list[float]:
        """Embed a single query string."""
        ...


@dataclass(slots=True)
class OllamaEmbedder:
    """Embeds text using a local Ollama embedding model.

    The Ollama client is created lazily on first use; the host defaults to the
    configured Ollama base URL.
    """

    model: str
    host: str = ""
    _client: Any = None

    def _ollama(self) -> Any:
        if self._client is None:
            from ollama import Client

            self._client = Client(host=self.host or None)
        return self._client

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        batch = list(texts)
        if not batch:
            return []
        try:
            response = self._ollama().embed(model=self.model, input=batch)
        except Exception as exc:
            raise ToolExecutionError(
                f"Ollama embedding failed (model '{self.model}'): {exc}"
            ) from exc
        return [[float(value) for value in vector] for vector in response.embeddings]

    def embed_query(self, text: str) -> list[float]:
        vectors = self.embed_documents([text])
        if not vectors:
            raise ToolExecutionError("Ollama returned no embedding for the query")
        return vectors[0]
