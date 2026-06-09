"""Document loaders that turn local corpora into knowledge-base documents.

Each loader yields :class:`KBDocument` objects tagged with a ``source`` so the
store can filter retrieval by corpus. All loaders are pure with respect to the
filesystem inputs they are given, which keeps them unit-testable without a SIEM,
Ollama, or the network.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from adept.coverage.rules import load_rules
from adept.kb.models import KBDocument
from adept.shared.logging import get_logger

log = get_logger(__name__)


def chunk_text(text: str, *, chunk_chars: int = 1200, overlap: int = 150) -> list[str]:
    """Split ``text`` into overlapping character windows for embedding."""
    text = text.strip()
    if not text:
        return []
    size = max(1, chunk_chars)
    if len(text) <= size:
        return [text]
    step = max(1, size - max(0, overlap))
    chunks: list[str] = []
    for start in range(0, len(text), step):
        window = text[start : start + size].strip()
        if window:
            chunks.append(window)
        if start + size >= len(text):
            break
    return chunks


def iter_rule_documents(rules_dir: Path | str, *, source: str) -> Iterator[KBDocument]:
    """Yield a document per Sigma rule found under ``rules_dir``."""
    for info in load_rules(Path(rules_dir)):
        path = Path(info.path)
        try:
            body = path.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("kb.rule_read_failed", path=str(path), error=str(exc))
            continue
        techniques = ", ".join(sorted(info.technique_ids))
        header = f"Sigma rule: {info.title}"
        if techniques:
            header += f"\nATT&CK techniques: {techniques}"
        yield KBDocument(
            id=f"{source}:{info.rule_id or path.stem}",
            text=f"{header}\n\n{body}",
            source=source,
            title=info.title,
            metadata={
                "path": str(path),
                "product": info.product,
                "category": info.category,
                "techniques": techniques,
                "tactics": ", ".join(sorted(info.tactics)),
            },
        )


def iter_homelab_documents(
    doc_path: Path | str, *, chunk_chars: int = 1200, overlap: int = 150
) -> Iterator[KBDocument]:
    """Yield chunked documents from the homelab architecture markdown file."""
    path = Path(doc_path)
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    for index, chunk in enumerate(chunk_text(text, chunk_chars=chunk_chars, overlap=overlap)):
        yield KBDocument(
            id=f"homelab:{path.stem}:{index}",
            text=chunk,
            source="homelab",
            title=path.stem,
            metadata={"path": str(path), "chunk": str(index)},
        )


def _format_metadata(data: dict[str, Any]) -> str:
    """Render a rule metadata sidecar into a readable tuning summary."""
    lines: list[str] = []
    rule_id = data.get("rule_id")
    if rule_id:
        lines.append(f"Rule: {rule_id}")
    for key in ("title", "stage", "owner", "false_positive_rate"):
        value = data.get(key)
        if value not in (None, ""):
            lines.append(f"{key.replace('_', ' ').title()}: {value}")
    mitre = data.get("mitre")
    if isinstance(mitre, dict):
        for key in ("tactics", "techniques"):
            values = mitre.get(key)
            if values:
                joined = ", ".join(str(item) for item in values)
                lines.append(f"ATT&CK {key}: {joined}")
    change_log = data.get("change_log")
    if isinstance(change_log, list) and change_log:
        lines.append("Change log:")
        for entry in change_log:
            if isinstance(entry, dict):
                date = entry.get("date", "")
                note = entry.get("change") or entry.get("note") or ""
                lines.append(f"  - {date}: {note}".rstrip())
            else:
                lines.append(f"  - {entry}")
    return "\n".join(lines)


def iter_tuning_documents(metadata_dir: Path | str) -> Iterator[KBDocument]:
    """Yield a document per rule metadata sidecar (tuning history)."""
    base = Path(metadata_dir)
    if not base.is_dir():
        return
    for path in sorted(base.rglob("*.meta.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            log.warning("kb.meta_read_failed", path=str(path), error=str(exc))
            continue
        if not isinstance(data, dict):
            continue
        summary = _format_metadata(data)
        if not summary.strip():
            continue
        rule_id = str(data.get("rule_id") or path.stem)
        yield KBDocument(
            id=f"tuning:{rule_id}",
            text=summary,
            source="tuning",
            title=rule_id,
            metadata={"path": str(path), "stage": str(data.get("stage", ""))},
        )


def _get(obj: Any, key: str, default: Any) -> Any:
    """Read ``key`` from a STIX object via mapping access or attribute access."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    getter = getattr(obj, "get", None)
    if callable(getter):
        try:
            return getter(key, default)
        except TypeError:
            pass
    return getattr(obj, key, default)


def _external_id(obj: Any) -> str:
    for ref in _get(obj, "external_references", []) or []:
        if _get(ref, "source_name", "") == "mitre-attack":
            return str(_get(ref, "external_id", "") or "")
    return ""


def _kill_chain_tactics(obj: Any) -> list[str]:
    tactics: list[str] = []
    for phase in _get(obj, "kill_chain_phases", []) or []:
        if _get(phase, "kill_chain_name", "") == "mitre-attack":
            name = str(_get(phase, "phase_name", "") or "")
            if name:
                tactics.append(name)
    return tactics


def attack_document(obj: Any) -> KBDocument | None:
    """Build a knowledge-base document from a STIX ATT&CK technique object."""
    technique_id = _external_id(obj)
    if not technique_id:
        return None
    name = str(_get(obj, "name", "") or "")
    description = str(_get(obj, "description", "") or "")
    tactics = _kill_chain_tactics(obj)
    platforms = [str(p) for p in (_get(obj, "x_mitre_platforms", []) or [])]
    detection = str(_get(obj, "x_mitre_detection", "") or "")
    title = f"{technique_id} {name}".strip()
    parts = [title]
    if tactics:
        parts.append("Tactics: " + ", ".join(tactics))
    if platforms:
        parts.append("Platforms: " + ", ".join(platforms))
    if description:
        parts.append(description)
    if detection:
        parts.append("Detection: " + detection)
    return KBDocument(
        id=f"attack:{technique_id}",
        text="\n\n".join(parts),
        source="attack",
        title=title,
        metadata={
            "technique_id": technique_id,
            "tactics": ", ".join(tactics),
            "platforms": ", ".join(platforms),
        },
    )


def iter_attack_documents(stix_filepath: Path | str) -> Iterator[KBDocument]:
    """Yield a document per ATT&CK technique from a local STIX bundle."""
    from mitreattack.stix20 import MitreAttackData

    data = MitreAttackData(str(stix_filepath))
    for obj in data.get_techniques(remove_revoked_deprecated=True):
        document = attack_document(obj)
        if document is not None:
            yield document
