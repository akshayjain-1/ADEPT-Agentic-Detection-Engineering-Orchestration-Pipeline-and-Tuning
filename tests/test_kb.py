"""Offline tests for the RAG knowledge base.

A deterministic bag-of-words fake embedder stands in for Ollama, and a temporary
on-disk Chroma collection is used, so these tests need neither a running Ollama
server nor the network.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from pathlib import Path

import pytest
from adept.config.settings import Settings
from adept.kb.models import KBDocument
from adept.kb.service import ALL_SOURCES, KnowledgeBase
from adept.kb.sources import (
    attack_document,
    chunk_text,
    iter_homelab_documents,
    iter_rule_documents,
    iter_tuning_documents,
)
from adept.kb.store import VectorStore
from adept.shared.errors import ToolExecutionError

_RULE_YAML = """
title: Whoami Execution
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \\whoami.exe
    condition: selection
tags:
    - attack.discovery
    - attack.t1033
"""

_META_YAML = """
rule_id: 11111111-1111-1111-1111-111111111111
title: Whoami Execution
stage: testing
owner: blue-team
false_positive_rate: low
mitre:
    tactics: [discovery]
    techniques: [T1033]
change_log:
    - date: 2026-01-01
      change: Initial draft
    - date: 2026-02-01
      change: Tuned to reduce admin noise
"""


class _FakeEmbedder:
    """Deterministic bag-of-words embedder (stable across runs, no Ollama)."""

    dim = 96

    def _vector(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in re.findall(r"[a-z0-9]+", text.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            vec[int(digest, 16) % self.dim] += 1.0
        return vec

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._vector(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._vector(text)


def _store(tmp_path: Path) -> VectorStore:
    return VectorStore(
        persist_dir=tmp_path / "chroma",
        collection_name="adept_test_kb",
        embedder=_FakeEmbedder(),
    )


def _kb_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("ADEPT_SIGMA__PATH", str(tmp_path / "sigma"))
    monkeypatch.setenv("ADEPT_DOCS_DIR", str(tmp_path / "docs"))
    monkeypatch.setenv("ADEPT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADEPT_KB__PERSIST_DIR", str(tmp_path / "chroma"))
    monkeypatch.setenv("ADEPT_KB__COLLECTION", "adept_test_kb")
    return Settings(_env_file=None)  # type: ignore[call-arg]


# --------------------------------------------------------------------------- #
# chunking
# --------------------------------------------------------------------------- #
def test_chunk_text_short_returns_single() -> None:
    assert chunk_text("a short note") == ["a short note"]


def test_chunk_text_long_splits_with_overlap() -> None:
    text = " ".join(f"word{i}" for i in range(400))
    chunks = chunk_text(text, chunk_chars=200, overlap=50)
    assert len(chunks) > 1
    assert all(len(chunk) <= 200 for chunk in chunks)


# --------------------------------------------------------------------------- #
# vector store
# --------------------------------------------------------------------------- #
def test_store_upsert_and_search_ranks_relevant_first(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert(
        [
            KBDocument(
                id="own:1",
                text="whoami discovery process creation",
                source="own_rules",
                title="Whoami",
            ),
            KBDocument(
                id="attack:T1003",
                text="credential dumping lsass memory",
                source="attack",
                title="T1003",
            ),
            KBDocument(
                id="homelab:0",
                text="proxmox network topology vlan",
                source="homelab",
                title="homelab",
            ),
        ]
    )
    result = store.search("whoami discovery", n_results=3)
    assert result.total == 3
    assert result.hits[0].id == "own:1"
    assert result.hits[0].source == "own_rules"
    assert result.hits[0].title == "Whoami"
    assert isinstance(result.hits[0].score, float)


def test_store_search_filters_by_source(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert(
        [
            KBDocument(id="own:1", text="whoami discovery", source="own_rules", title="A"),
            KBDocument(id="attack:T1003", text="whoami discovery", source="attack", title="B"),
        ]
    )
    result = store.search("whoami discovery", n_results=5, sources=["attack"])
    assert {hit.source for hit in result.hits} == {"attack"}


def test_store_search_filters_by_multiple_sources(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert(
        [
            KBDocument(id="own:1", text="whoami discovery", source="own_rules", title="A"),
            KBDocument(id="attack:T1003", text="whoami discovery", source="attack", title="B"),
            KBDocument(id="homelab:0", text="whoami discovery", source="homelab", title="C"),
        ]
    )
    result = store.search("whoami discovery", n_results=5, sources=["attack", "homelab"])
    assert {hit.source for hit in result.hits} == {"attack", "homelab"}


def test_store_upsert_is_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    docs = [KBDocument(id="own:1", text="whoami discovery", source="own_rules", title="A")]
    store.upsert(docs)
    store.upsert(docs)
    assert store.count() == 1


def test_store_preserves_custom_metadata(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert(
        [
            KBDocument(
                id="own:1",
                text="whoami discovery",
                source="own_rules",
                title="A",
                metadata={"product": "windows", "techniques": "T1033"},
            )
        ]
    )
    hit = store.search("whoami", n_results=1).hits[0]
    assert hit.metadata["product"] == "windows"
    assert hit.metadata["techniques"] == "T1033"


# --------------------------------------------------------------------------- #
# source loaders
# --------------------------------------------------------------------------- #
def test_iter_rule_documents(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "whoami.yml").write_text(_RULE_YAML, encoding="utf-8")
    docs = list(iter_rule_documents(rules_dir, source="own_rules"))
    assert len(docs) == 1
    doc = docs[0]
    assert doc.source == "own_rules"
    assert doc.title == "Whoami Execution"
    assert "whoami.exe" in doc.text
    assert doc.metadata["techniques"] == "T1033"
    assert doc.metadata["product"] == "windows"


def test_iter_homelab_documents_chunks(tmp_path: Path) -> None:
    doc_path = tmp_path / "homelab_architecture.md"
    doc_path.write_text(" ".join(f"line{i}" for i in range(500)), encoding="utf-8")
    docs = list(iter_homelab_documents(doc_path, chunk_chars=200, overlap=40))
    assert len(docs) > 1
    assert all(doc.source == "homelab" for doc in docs)
    assert docs[0].metadata["chunk"] == "0"


def test_iter_homelab_documents_missing_file(tmp_path: Path) -> None:
    assert list(iter_homelab_documents(tmp_path / "nope.md")) == []


def test_iter_tuning_documents(tmp_path: Path) -> None:
    meta_dir = tmp_path / "metadata"
    meta_dir.mkdir()
    (meta_dir / "whoami.meta.yml").write_text(_META_YAML, encoding="utf-8")
    docs = list(iter_tuning_documents(meta_dir))
    assert len(docs) == 1
    doc = docs[0]
    assert doc.source == "tuning"
    assert doc.metadata["stage"] == "testing"
    assert "Initial draft" in doc.text
    assert "Tuned to reduce admin noise" in doc.text


def test_attack_document_builds_from_stix() -> None:
    stix = {
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command interpreters.",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1059",
                "url": "https://attack.mitre.org/T1059",
            }
        ],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        "x_mitre_platforms": ["Windows", "Linux"],
        "x_mitre_detection": "Monitor process creation.",
    }
    doc = attack_document(stix)
    assert doc is not None
    assert doc.id == "attack:T1059"
    assert doc.source == "attack"
    assert "execution" in doc.text
    assert "command interpreters" in doc.text
    assert doc.metadata["technique_id"] == "T1059"
    assert doc.metadata["platforms"] == "Windows, Linux"


def test_attack_document_without_id_returns_none() -> None:
    assert attack_document({"name": "x", "external_references": []}) is None


# --------------------------------------------------------------------------- #
# KnowledgeBase orchestration
# --------------------------------------------------------------------------- #
def _seed_corpus(tmp_path: Path) -> None:
    rules_dir = tmp_path / "sigma" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "whoami.yml").write_text(_RULE_YAML, encoding="utf-8")
    meta_dir = tmp_path / "sigma" / "metadata"
    meta_dir.mkdir(parents=True)
    (meta_dir / "whoami.meta.yml").write_text(_META_YAML, encoding="utf-8")
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True)
    (docs_dir / "homelab_architecture.md").write_text(
        "Proxmox cluster with Wazuh, ELK, and Splunk SIEMs over Tailscale.",
        encoding="utf-8",
    )


def test_knowledge_base_ingest_and_search(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_corpus(tmp_path)
    settings = _kb_settings(tmp_path, monkeypatch)
    kb = KnowledgeBase(store=_store(tmp_path), settings=settings)

    report = kb.ingest(["own_rules", "homelab", "tuning"])
    assert report.by_source["own_rules"] == 1
    assert report.by_source["tuning"] == 1
    assert report.by_source["homelab"] >= 1
    assert report.skipped_sources == []
    assert report.total_indexed == kb.count()

    hits = kb.search("whoami discovery", n_results=3).hits
    assert hits
    assert hits[0].source == "own_rules"


def test_knowledge_base_skips_unconfigured_sigmahq(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_corpus(tmp_path)
    settings = _kb_settings(tmp_path, monkeypatch)
    kb = KnowledgeBase(store=_store(tmp_path), settings=settings)
    report = kb.ingest(["sigmahq"])
    assert report.total_indexed == 0
    assert report.skipped_sources == ["sigmahq"]


def test_knowledge_base_rejects_unknown_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _kb_settings(tmp_path, monkeypatch)
    kb = KnowledgeBase(store=_store(tmp_path), settings=settings)
    with pytest.raises(ToolExecutionError):
        kb.ingest(["bogus"])


def test_all_sources_constant() -> None:
    assert ALL_SOURCES == ("own_rules", "attack", "homelab", "tuning", "sigmahq")
