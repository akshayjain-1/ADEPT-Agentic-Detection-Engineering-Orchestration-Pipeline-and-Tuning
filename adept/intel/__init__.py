"""Threat-intelligence integrations for ADEPT.

Provides typed, cached, allowlist-guarded clients for:

* **NVD** — CVE lookup and keyword search (CVE API 2.0).
* **CISA KEV** — the Known Exploited Vulnerabilities catalogue.
* **MITRE ATT&CK** — enterprise technique lookup from the official STIX bundle.
* **Security news** — recent items from configured RSS/Atom feeds.

:class:`IntelService` is the composition root used by the MCP tool layer.
"""

from __future__ import annotations

from adept.intel.attack import AttackClient, parse_technique, validate_attack_id
from adept.intel.http import IntelHTTP, host_allowed
from adept.intel.kev import KEVClient, parse_kev_entry
from adept.intel.models import (
    AttackTechnique,
    CVERecord,
    CVESearchResult,
    CVSSMetric,
    KEVEntry,
    KEVResult,
    NewsItem,
    NewsResult,
)
from adept.intel.news import NewsClient, feed_hosts, parse_feed
from adept.intel.nvd import (
    NVDClient,
    parse_cve,
    parse_cve_response,
    validate_cve_id,
)
from adept.intel.service import IntelService

__all__ = [
    "AttackClient",
    "AttackTechnique",
    "CVERecord",
    "CVESearchResult",
    "CVSSMetric",
    "IntelHTTP",
    "IntelService",
    "KEVClient",
    "KEVEntry",
    "KEVResult",
    "NVDClient",
    "NewsClient",
    "NewsItem",
    "NewsResult",
    "feed_hosts",
    "host_allowed",
    "parse_cve",
    "parse_cve_response",
    "parse_feed",
    "parse_kev_entry",
    "parse_technique",
    "validate_attack_id",
    "validate_cve_id",
]
