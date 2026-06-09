"""CISA Known Exploited Vulnerabilities (KEV) client.

The KEV catalogue is a single JSON document, so it is fetched once and cached
with a long TTL, then filtered client-side (by CVE id or free-text query).
"""

from __future__ import annotations

from typing import Any

from adept.intel.http import IntelHTTP
from adept.intel.models import KEVEntry, KEVResult


def parse_kev_entry(raw: dict[str, Any]) -> KEVEntry:
    """Normalise one raw KEV vulnerability object."""
    return KEVEntry(
        cve_id=str(raw.get("cveID", "")),
        vendor_project=str(raw.get("vendorProject", "")),
        product=str(raw.get("product", "")),
        name=str(raw.get("vulnerabilityName", "")),
        date_added=str(raw.get("dateAdded", "")),
        due_date=str(raw.get("dueDate", "")),
        short_description=str(raw.get("shortDescription", "")),
        required_action=str(raw.get("requiredAction", "")),
        known_ransomware=str(raw.get("knownRansomwareCampaignUse", "")),
    )


def _matches(entry: KEVEntry, query: str) -> bool:
    needle = query.lower()
    return (
        needle
        in " ".join(
            [
                entry.cve_id,
                entry.vendor_project,
                entry.product,
                entry.name,
                entry.short_description,
            ]
        ).lower()
    )


class KEVClient:
    """Fetch and filter the CISA KEV catalogue."""

    def __init__(self, http: IntelHTTP, *, url: str, ttl_seconds: int = 0):
        self._http = http
        self._url = url
        self._ttl = ttl_seconds

    def _catalog(self) -> dict[str, Any]:
        data = self._http.get_json(self._url, cache_key="cisa:kev:catalog", ttl_seconds=self._ttl)
        return data if isinstance(data, dict) else {}

    def get_kev(
        self, *, cve_id: str | None = None, query: str | None = None, limit: int = 50
    ) -> KEVResult:
        """Return KEV entries, optionally filtered by CVE id or free-text query."""
        catalog = self._catalog()
        raw_entries = catalog.get("vulnerabilities", [])
        entries = [parse_kev_entry(item) for item in raw_entries if isinstance(item, dict)]

        if cve_id:
            wanted = cve_id.strip().upper()
            entries = [entry for entry in entries if entry.cve_id.upper() == wanted]
        elif query:
            entries = [entry for entry in entries if _matches(entry, query)]

        capped = entries[: max(1, limit)]
        return KEVResult(
            catalog_version=str(catalog.get("catalogVersion", "")),
            date_released=str(catalog.get("dateReleased", "")),
            total=len(entries),
            returned=len(capped),
            entries=capped,
        )
