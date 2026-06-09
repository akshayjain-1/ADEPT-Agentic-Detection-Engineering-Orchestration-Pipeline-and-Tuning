"""Pydantic models for the RAG knowledge base."""

from __future__ import annotations

from pydantic import BaseModel, Field


class KBDocument(BaseModel):
    """A single document to index in the vector store."""

    id: str
    text: str
    source: str
    title: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class KBSearchHit(BaseModel):
    """One retrieved document with its relevance score."""

    id: str
    source: str
    title: str
    score: float
    text: str
    metadata: dict[str, str] = Field(default_factory=dict)


class KBSearchResult(BaseModel):
    """The ranked results of a knowledge-base query."""

    query: str
    total: int
    hits: list[KBSearchHit] = Field(default_factory=list)


class IngestReport(BaseModel):
    """Summary of a knowledge-base ingestion run."""

    collection: str
    total_indexed: int
    by_source: dict[str, int] = Field(default_factory=dict)
    skipped_sources: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
