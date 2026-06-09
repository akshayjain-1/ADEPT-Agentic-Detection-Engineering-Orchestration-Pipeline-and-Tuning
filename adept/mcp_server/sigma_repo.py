"""Git-backed Sigma rule repository operations.

Wraps a local clone of the detection-rules repo (``sigma_rules/`` during
bootstrap) and exposes safe, auditable primitives the MCP tools build on:
listing/reading/writing rules, branch management, commits, and diffs.

Security:
  * All rule paths are confined to the ``rules/`` directory; path-traversal
    attempts raise :class:`SecurityError`.
  * Commits to a protected branch (e.g. ``main``) are refused unless explicitly
    allowed, steering changes through branches and the human approval gate.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import git
import yaml
from pydantic import BaseModel

from adept.shared.errors import SecurityError, ValidationFailedError
from adept.shared.logging import get_logger

log = get_logger(__name__)

# --- SigmaHQ-style filename derivation ---------------------------------------
#
# Rule filenames are generated from the rule's own ``logsource`` + ``title`` so
# the server owns the name and the model cannot misname a rule (e.g. with a
# placeholder UUID). The name is built from the rule, so it never depends on a
# matching file already existing in SigmaHQ.

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_MAX_SLUG_LEN = 80

#: ``rules/windows/<folder>`` + filename prefix, keyed by logsource *category*.
_WINDOWS_CATEGORY: dict[str, tuple[str, str]] = {
    "process_creation": ("process_creation", "proc_creation_win"),
    "image_load": ("image_load", "image_load_win"),
    "network_connection": ("network_connection", "net_connection_win"),
    "dns_query": ("dns_query", "dns_query_win"),
    "create_remote_thread": ("create_remote_thread", "create_remote_thread_win"),
    "create_stream_hash": ("create_stream_hash", "create_stream_hash_win"),
    "pipe_created": ("pipe_created", "pipe_created_win"),
    "wmi_event": ("wmi_event", "wmi_event_win"),
    "driver_load": ("driver_load", "driver_load_win"),
    "raw_access_thread": ("raw_access_thread", "raw_access_thread_win"),
    "registry_set": ("registry/registry_set", "registry_set_win"),
    "registry_add": ("registry/registry_add", "registry_add_win"),
    "registry_delete": ("registry/registry_delete", "registry_delete_win"),
    "registry_event": ("registry/registry_event", "registry_event_win"),
    "registry_rename": ("registry/registry_rename", "registry_rename_win"),
    "file_event": ("file/file_event", "file_event_win"),
    "file_delete": ("file/file_delete", "file_delete_win"),
    "file_rename": ("file/file_rename", "file_rename_win"),
    "file_access": ("file/file_access", "file_access_win"),
    "file_change": ("file/file_change", "file_change_win"),
    "ps_script": ("powershell/powershell_script", "posh_ps"),
    "ps_module": ("powershell/powershell_module", "posh_pm"),
    "ps_classic_start": ("powershell/powershell_classic", "posh_pc"),
}

#: ``rules/windows/<folder>`` + filename prefix, keyed by logsource *service*.
_WINDOWS_SERVICE: dict[str, tuple[str, str]] = {
    "security": ("builtin/security", "win_security"),
    "system": ("builtin/system", "win_system"),
    "application": ("builtin/application", "win_application"),
    "powershell": ("builtin/powershell", "win_powershell"),
    "powershell-classic": ("builtin/powershell", "win_powershell_classic"),
    "taskscheduler": ("builtin/taskscheduler", "win_taskscheduler"),
    "windefend": ("builtin/windefend", "win_defender"),
    "security-mitigations": ("builtin/security-mitigations", "win_security_mitigations"),
    "ntlm": ("builtin/ntlm", "win_ntlm"),
    "applocker": ("builtin/applocker", "win_applocker"),
    "wmi": ("builtin/wmi", "win_wmi"),
    "dns-server": ("builtin/dns-server", "win_dns_server"),
    "bits-client": ("builtin/bits-client", "win_bits_client"),
    "firewall-as": ("builtin/firewall-as", "win_firewall_as"),
}

#: Product abbreviations used in filename prefixes for non-Windows products.
_PRODUCT_ABBR: dict[str, str] = {"windows": "win", "linux": "lnx", "macos": "macos"}

#: Short, product-independent prefixes for categories whose abbreviation is not
#: simply the category name (used by the generic, non-Windows fallback).
_CATEGORY_PREFIX: dict[str, str] = {
    "process_creation": "proc_creation",
    "network_connection": "net_connection",
}


def _slugify(text: str) -> str:
    """Lowercase ASCII, underscore-separated slug, capped to a sane length."""
    slug = _SLUG_RE.sub("_", text.strip().lower()).strip("_")
    if len(slug) > _MAX_SLUG_LEN:
        slug = slug[:_MAX_SLUG_LEN].rstrip("_")
    return slug


def _generic_location(product: str, category: str, service: str) -> tuple[str, str]:
    """Fallback ``(folder, prefix)`` for products/logsources without a mapping."""
    base = _slugify(product) or "other"
    key = category or service or "other"
    folder = f"{base}/{_slugify(key)}"
    short = _CATEGORY_PREFIX.get(category, _slugify(key))
    abbr = _PRODUCT_ABBR.get(product)
    prefix = f"{short}_{abbr}" if abbr else short
    return folder, prefix


def _logsource_location(product: str, category: str, service: str) -> tuple[str, str]:
    """Map a logsource to its ``(folder-under-rules, filename-prefix)``."""
    if product == "windows":
        if category in _WINDOWS_CATEGORY:
            sub, prefix = _WINDOWS_CATEGORY[category]
            return f"windows/{sub}", prefix
        if service in _WINDOWS_SERVICE:
            sub, prefix = _WINDOWS_SERVICE[service]
            return f"windows/{sub}", prefix
    return _generic_location(product, category, service)


def derive_rule_path(doc: Mapping[str, Any]) -> str:
    """Derive a SigmaHQ-style, repo-relative rule path from rule content.

    The filename follows the SigmaHQ convention ``<prefix>_<behavior>.yml`` where
    the prefix and folder come from the rule's ``logsource`` and the behavior is a
    slug of its ``title``. Because the name is built from the rule itself, it never
    depends on a matching file already existing in SigmaHQ.

    Returns a path relative to ``rules/``, e.g.
    ``windows/process_creation/proc_creation_win_whoami_execution.yml``.

    Raises:
        ValidationFailedError: if the rule lacks a usable ``title`` or ``logsource``.
    """
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        raise ValidationFailedError(
            "Rule must have a non-empty 'title' so a filename can be derived."
        )
    behavior = _slugify(title)
    if not behavior:
        raise ValidationFailedError(
            f"Could not derive a filename from title {title!r}; use a descriptive ASCII title."
        )
    logsource = doc.get("logsource")
    if not isinstance(logsource, dict):
        raise ValidationFailedError(
            "Rule must have a 'logsource' mapping so a filename can be derived."
        )
    product = str(logsource.get("product") or "").strip().lower()
    category = str(logsource.get("category") or "").strip().lower()
    service = str(logsource.get("service") or "").strip().lower()
    if not (product or category or service):
        raise ValidationFailedError(
            "Rule 'logsource' must set at least one of product/category/service."
        )
    folder, prefix = _logsource_location(product, category, service)
    return f"{folder}/{prefix}_{behavior}.yml"


class RuleRef(BaseModel):
    """Lightweight summary of a Sigma rule on disk."""

    path: str  # repo-relative, e.g. "rules/windows/process_creation/x.yml"
    id: str | None = None
    title: str | None = None
    status: str | None = None
    level: str | None = None
    product: str | None = None
    category: str | None = None
    service: str | None = None
    tags: list[str] = []


class SigmaRepo:
    """A local git working copy of the Sigma detection rules."""

    def __init__(
        self,
        root: Path,
        *,
        default_branch: str = "main",
        protected_branches: Sequence[str] = ("main",),
        remote: str | None = None,
    ) -> None:
        self.root = root.resolve()
        self.default_branch = default_branch
        self.protected_branches = set(protected_branches)
        self.remote = remote

    # --- repository lifecycle -------------------------------------------------

    @property
    def rules_dir(self) -> Path:
        return self.root / "rules"

    def ensure_repo(self) -> git.Repo:
        """Open the repo, initialising it (and ``rules/``) if necessary."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        if (self.root / ".git").exists():
            repo = git.Repo(self.root)
        else:
            repo = git.Repo.init(self.root)
            # Name the (possibly unborn) default branch deterministically.
            repo.git.symbolic_ref("HEAD", f"refs/heads/{self.default_branch}")
            log.info("sigma_repo_initialised", root=str(self.root), branch=self.default_branch)
        self._ensure_identity(repo)
        return repo

    @staticmethod
    def _ensure_identity(repo: git.Repo) -> None:
        """Set a local commit identity if neither local nor global is configured."""
        with repo.config_reader() as reader:
            if reader.has_option("user", "name") and reader.has_option("user", "email"):
                return
        with repo.config_writer() as writer:
            writer.set_value("user", "name", "ADEPT")
            writer.set_value("user", "email", "adept@localhost")

    def _repo(self) -> git.Repo:
        return git.Repo(self.root)

    # --- path safety ----------------------------------------------------------

    def _safe_rule_path(self, rel: str) -> Path:
        """Resolve a user-supplied rule path safely within ``rules/``."""
        candidate = rel.replace("\\", "/").strip().lstrip("/")
        if candidate.startswith("rules/"):
            candidate = candidate[len("rules/") :]
        resolved = (self.rules_dir / candidate).resolve()
        rules_root = self.rules_dir.resolve()
        if resolved != rules_root and rules_root not in resolved.parents:
            raise SecurityError(f"Rule path escapes the rules directory: {rel!r}")
        if resolved.suffix not in {".yml", ".yaml"}:
            raise SecurityError(f"Rule path must be a YAML file: {rel!r}")
        return resolved

    def _rel(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    # --- rule access ----------------------------------------------------------

    def list_rules(self) -> list[RuleRef]:
        refs: list[RuleRef] = []
        if not self.rules_dir.exists():
            return refs
        for path in sorted(self.rules_dir.rglob("*.yml")):
            if path.name.endswith(".meta.yml"):
                continue
            refs.append(self._summarise(path))
        return refs

    def _summarise(self, path: Path) -> RuleRef:
        ref = RuleRef(path=self._rel(path))
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            log.warning("rule_parse_failed", path=ref.path, error=str(exc))
            return ref
        if not isinstance(doc, dict):
            return ref
        ref.id = doc.get("id")
        ref.title = doc.get("title")
        ref.status = doc.get("status")
        ref.level = doc.get("level")
        tags = doc.get("tags")
        ref.tags = [str(t) for t in tags] if isinstance(tags, list) else []
        logsource = doc.get("logsource")
        if isinstance(logsource, dict):
            ref.product = logsource.get("product")
            ref.category = logsource.get("category")
            ref.service = logsource.get("service")
        return ref

    def read_rule(self, rel: str) -> str:
        path = self._safe_rule_path(rel)
        if not path.exists():
            raise ValidationFailedError(f"Rule not found: {rel!r}")
        return path.read_text(encoding="utf-8")

    @staticmethod
    def _parse_rule(content: str) -> dict[str, Any]:
        """Parse a single Sigma YAML document into a mapping (or raise)."""
        try:
            parsed = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ValidationFailedError(f"Rule is not valid YAML: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValidationFailedError("Rule must be a YAML mapping")
        return parsed

    def write_rule(self, rel: str, content: str, *, parse_check: bool = True) -> str:
        path = self._safe_rule_path(rel)
        if parse_check:
            self._parse_rule(content)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
        rel_path = self._rel(path)
        log.info("rule_written", path=rel_path)
        return rel_path

    def write_derived_rule(self, content: str) -> str:
        """Write a rule to a path derived from its own ``title`` + ``logsource``.

        The server owns the filename (see :func:`derive_rule_path`) so the model
        cannot misname a rule. Writing the same rule again resolves to the same
        path and updates it in place. Returns the repo-relative path written.
        """
        doc = self._parse_rule(content)
        rel = derive_rule_path(doc)
        return self.write_rule(rel, content, parse_check=False)

    # --- branches & commits ---------------------------------------------------

    def current_branch(self) -> str:
        repo = self._repo()
        try:
            return repo.active_branch.name
        except (TypeError, ValueError):
            return self.default_branch

    def list_branches(self) -> list[str]:
        return [h.name for h in self._repo().heads]

    def is_protected(self, branch: str) -> bool:
        return branch in self.protected_branches

    def create_branch(self, name: str, *, checkout: bool = True) -> None:
        repo = self._repo()
        if name in [h.name for h in repo.heads]:
            if checkout:
                repo.git.checkout(name)
            return
        # A branch can only be created once there is at least one commit.
        if repo.head.is_valid():
            repo.create_head(name)
            if checkout:
                repo.git.checkout(name)
        else:
            repo.git.checkout("-b", name)

    def checkout(self, name: str) -> None:
        self._repo().git.checkout(name)

    def commit(
        self,
        paths: Iterable[str],
        message: str,
        *,
        allow_protected: bool = False,
    ) -> str:
        repo = self._repo()
        branch = self.current_branch()
        if self.is_protected(branch) and not allow_protected:
            raise SecurityError(
                f"Refusing to commit directly to protected branch {branch!r}; "
                "use a feature branch and the approval gate."
            )
        rel_paths = [self._rel(self._safe_rule_path(p)) for p in paths]
        repo.index.add(rel_paths)
        commit = repo.index.commit(message)
        log.info("rule_committed", branch=branch, commit=commit.hexsha, paths=rel_paths)
        return commit.hexsha

    def diff(self, *, staged: bool = False, ref: str | None = None) -> str:
        repo = self._repo()
        if ref:
            return repo.git.diff(ref)
        if staged:
            return repo.git.diff("--cached")
        return repo.git.diff()
