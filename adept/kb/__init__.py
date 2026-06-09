"""ADEPT RAG knowledge base (Chroma vector store + Ollama embeddings)."""

from __future__ import annotations

from adept.kb.embeddings import Embedder, OllamaEmbedder
from adept.kb.models import IngestReport, KBDocument, KBSearchHit, KBSearchResult
from adept.kb.service import ALL_SOURCES, KnowledgeBase, available_sources
from adept.kb.sources import (
    attack_document,
    chunk_text,
    iter_attack_documents,
    iter_homelab_documents,
    iter_rule_documents,
    iter_tuning_documents,
)
from adept.kb.store import VectorStore

__all__ = [
    "ALL_SOURCES",
    "Embedder",
    "IngestReport",
    "KBDocument",
    "KBSearchHit",
    "KBSearchResult",
    "KnowledgeBase",
    "OllamaEmbedder",
    "VectorStore",
    "attack_document",
    "available_sources",
    "chunk_text",
    "iter_attack_documents",
    "iter_homelab_documents",
    "iter_rule_documents",
    "iter_tuning_documents",
]
