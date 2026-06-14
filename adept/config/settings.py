"""Typed application configuration for ADEPT.

All settings are sourced from environment variables (and an optional ``.env``
file) using ``pydantic-settings``. Settings are grouped into nested models;
their environment variables use a double-underscore delimiter and the
``ADEPT_`` prefix, e.g. the ``url`` field of :class:`ELKSettings` is set via
``ADEPT_ELK__URL``.

See ``.env.example`` for the full, documented surface.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# A list parsed from a comma-separated environment string (JSON decoding off).
CsvList = Annotated[list[str], NoDecode]


def _split_csv(value: object) -> object:
    """Split a comma-separated string into a clean list of items."""
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


# ---------------------------------------------------------------------------
# Component settings
# ---------------------------------------------------------------------------
class MCPSettings(BaseModel):
    """MCP server transport and authentication."""

    # Safe default: loopback only. Set to the Tailscale IP (or 0.0.0.0) to let
    # remote agents reach the server; exposure should stay gated by Tailscale.
    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"
    transport: Literal["streamable-http", "sse", "stdio"] = "streamable-http"
    auth_token: SecretStr = SecretStr("")
    public_url: str = "http://localhost:8765/mcp"


class OllamaSettings(BaseModel):
    """Local Ollama LLM + embedding configuration."""

    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5:7b-instruct"
    embed_model: str = "nomic-embed-text"
    temperature: float = 0.1
    num_ctx: int = 8192
    request_timeout: int = 180


class ELKSettings(BaseModel):
    """Elasticsearch / ELK (primary SIEM)."""

    enabled: bool = True
    url: str = "https://localhost:9200"
    api_key: SecretStr = SecretStr("")
    username: str = ""
    password: SecretStr = SecretStr("")
    verify_certs: bool = True
    ca_cert: str = ""
    default_index: str = "logs-*"
    # Kibana base URL for the Detection Engine deploy path (e.g. https://localhost:5601).
    kibana_url: str = ""
    # Index pattern that holds detection-engine alerts (for list_alerts).
    alerts_index: str = ".alerts-security.alerts-*"


class OpenSearchSettings(BaseModel):
    """Wazuh Indexer (OpenSearch)."""

    enabled: bool = False
    url: str = "https://localhost:9200"
    username: str = "admin"
    password: SecretStr = SecretStr("")
    verify_certs: bool = True
    ca_cert: str = ""
    default_index: str = "wazuh-alerts-*"


class SplunkSettings(BaseModel):
    """Splunk management API."""

    enabled: bool = False
    host: str = "localhost"
    port: int = 8089
    username: str = ""
    password: SecretStr = SecretStr("")
    token: SecretStr = SecretStr("")
    scheme: Literal["http", "https"] = "https"
    verify: bool = True
    default_index: str = "main"


class SigmaRepoSettings(BaseModel):
    """Local Sigma rules git repository."""

    path: Path = Path("./sigma_rules")
    default_branch: str = "main"
    protected_branches: CsvList = Field(default_factory=lambda: ["main", "release"])
    remote: str = ""

    _split = field_validator("protected_branches", mode="before")(_split_csv)


class IntelSettings(BaseModel):
    """External threat-intelligence sources."""

    nvd_api_key: SecretStr = SecretStr("")
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    attack_version: str = ""
    attack_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    rss_feeds: CsvList = Field(default_factory=list)
    allowed_domains: CsvList = Field(
        default_factory=lambda: [
            "services.nvd.nist.gov",
            "www.cisa.gov",
            "raw.githubusercontent.com",
        ]
    )
    # Caching keeps ADEPT responsive and a well-behaved API citizen.
    cache_ttl_seconds: int = 21600  # 6 hours for CVE/KEV lookups
    attack_cache_ttl_seconds: int = 604800  # 7 days for the ATT&CK STIX bundle
    # NVD allows ~5 requests / 30s without an API key, ~50 with one.
    nvd_rate_per_minute: float = 10.0

    _split = field_validator("rss_feeds", "allowed_domains", mode="before")(_split_csv)


class CoverageSettings(BaseModel):
    """ATT&CK coverage analysis settings."""

    # Default lookback window for SIEM field baseline profiling.
    baseline_lookback_days: int = 7


class KBSettings(BaseModel):
    """RAG knowledge base (Chroma + Ollama embeddings)."""

    persist_dir: Path = Path("./data/chroma")
    collection: str = "adept-knowledge"
    embed_model: str = "nomic-embed-text"
    # Chunking / batching for ingestion.
    chunk_chars: int = 1200
    chunk_overlap: int = 150
    batch_size: int = 64
    max_results: int = 5
    # Optional SigmaHQ community-rule ingestion (best-effort, opt-in).
    sigmahq_path: str = ""
    sigmahq_remote: str = ""
    sigmahq_clone: bool = False
    sigmahq_clone_timeout_seconds: int = 600


class NotifySettings(BaseModel):
    """Outbound notifications for approvals and deploy events."""

    backend: Literal["none", "ntfy", "discord", "slack", "webhook"] = "none"
    url: str = ""
    topic: str = ""
    token: SecretStr = SecretStr("")


class AttackSimSettings(BaseModel):
    """Atomic Red Team + Caldera attack-simulation guardrails.

    Defaults are deliberately safe: approval required, dry-run on, and only
    explicitly whitelisted Atomic technique IDs may even be proposed. Atomic
    Red Team is *propose-only* (ADEPT never executes atomics); Caldera
    operations are launched only behind the agent's human-approval gate.
    """

    require_approval: bool = True
    dry_run_default: bool = True
    atomic_enabled: bool = False
    atomic_allowed_tests: CsvList = Field(default_factory=list)
    # Local clone of redcanaryco/atomic-red-team; atomics live under <path>/atomics.
    atomic_path: str = ""
    caldera_enabled: bool = False
    caldera_url: str = ""
    caldera_api_key: SecretStr = SecretStr("")
    # HTTP header Caldera expects the API key in (Caldera's default is "KEY").
    caldera_api_key_header: str = "KEY"
    # Deployment-specific ids used when creating an operation; tune per server.
    caldera_planner_id: str = "atomic"
    caldera_source_id: str = "basic"
    caldera_default_group: str = ""
    caldera_timeout_seconds: int = 30

    _split = field_validator("atomic_allowed_tests", mode="before")(_split_csv)


class AgentSettings(BaseModel):
    """LangGraph agent runtime (runs next to Ollama)."""

    mcp_url: str = "http://localhost:8765/mcp"
    mcp_token: SecretStr = SecretStr("")
    mcp_timeout_seconds: int = 30
    # Empty model falls back to the shared Ollama model.
    model: str = ""
    checkpoint_db: Path = Path("./data/agent_history.sqlite")
    audit_log: Path = Path("./data/agent_audit.jsonl")
    recursion_limit: int = 50
    # Tools that require human approval before they execute (HITL gate).
    dangerous_tools: CsvList = Field(
        default_factory=lambda: [
            "siem_deploy_rule",
            "siem_disable_rule",
            "siem_delete_rule",
            "run_caldera_operation",
            "stop_caldera_operation",
        ]
    )
    # External editor for the "edit" approval action; empty uses $VISUAL/$EDITOR.
    editor: str = ""
    # Output guardrails. ``lint_enabled`` refuses illegal tool inputs (e.g. SPL
    # that pipes into ``| delete``) at submission; ``eval_enabled`` inserts the
    # evaluator node that lints each specialist's output and routes it back for
    # regeneration (up to ``eval_max_retries`` times) before escalating to the
    # human. ``llm_judge_enabled`` adds an optional, slower semantic critique.
    lint_enabled: bool = True
    eval_enabled: bool = True
    eval_max_retries: int = 2
    llm_judge_enabled: bool = False
    # Optional override of the built-in dangerous-SPL-command denylist (a
    # best-effort backstop behind the human approval gate); empty keeps the
    # built-in default. Add names here to also refuse argument-dependent
    # commands such as ``rest`` or ``map``.
    spl_denylist: CsvList = Field(default_factory=list)

    _split = field_validator("dangerous_tools", "spl_denylist", mode="before")(_split_csv)


class OTelSettings(BaseModel):
    """Optional OpenTelemetry tracing/metrics export."""

    enabled: bool = False
    endpoint: str = "http://localhost:4318"
    service_name: str = "adept"


# ---------------------------------------------------------------------------
# Top-level settings
# ---------------------------------------------------------------------------
class Settings(BaseSettings):
    """Root configuration object aggregating all component settings."""

    model_config = SettingsConfigDict(
        env_prefix="ADEPT_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    env: Literal["dev", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True
    data_dir: Path = Path("./data")
    docs_dir: Path = Path("./docs")

    mcp: MCPSettings = Field(default_factory=MCPSettings)
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    elk: ELKSettings = Field(default_factory=ELKSettings)
    opensearch: OpenSearchSettings = Field(default_factory=OpenSearchSettings)
    splunk: SplunkSettings = Field(default_factory=SplunkSettings)
    sigma: SigmaRepoSettings = Field(default_factory=SigmaRepoSettings)
    intel: IntelSettings = Field(default_factory=IntelSettings)
    coverage: CoverageSettings = Field(default_factory=CoverageSettings)
    kb: KBSettings = Field(default_factory=KBSettings)
    notify: NotifySettings = Field(default_factory=NotifySettings)
    attack: AttackSimSettings = Field(default_factory=AttackSimSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    otel: OTelSettings = Field(default_factory=OTelSettings)

    def enabled_siems(self) -> list[str]:
        """Return the identifiers of all enabled SIEM backends."""
        enabled: list[str] = []
        if self.elk.enabled:
            enabled.append("elk")
        if self.opensearch.enabled:
            enabled.append("opensearch")
        if self.splunk.enabled:
            enabled.append("splunk")
        return enabled

    def ensure_data_dir(self) -> Path:
        """Create the runtime data directory if needed and return it."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance.

    Cached so configuration is parsed once per process. Call
    ``get_settings.cache_clear()`` in tests that need to reload.
    """
    return Settings()
