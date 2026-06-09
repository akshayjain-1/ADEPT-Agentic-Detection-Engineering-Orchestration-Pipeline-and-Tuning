"""NVD CVE API 2.0 client.

Looks up a single CVE or searches by keyword via the verified NVD 2.0 REST API,
normalising the verbose response into :class:`CVERecord`. Parsing is split into
pure functions so it can be unit-tested without network access.
"""

from __future__ import annotations

import re
from typing import Any

from adept.intel.http import IntelHTTP
from adept.intel.models import CVERecord, CVESearchResult, CVSSMetric
from adept.shared.errors import ValidationFailedError

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def validate_cve_id(cve_id: str) -> str:
    """Return the normalised CVE id or raise if it is malformed."""
    candidate = cve_id.strip().upper()
    if not _CVE_ID_RE.match(candidate):
        raise ValidationFailedError(f"invalid CVE id: {cve_id!r} (expected CVE-YYYY-NNNN)")
    return candidate


def _english_description(cve: dict[str, Any]) -> str:
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return str(entry.get("value", ""))
    return ""


def _parse_metrics(cve: dict[str, Any]) -> list[CVSSMetric]:
    metrics_obj = cve.get("metrics", {})
    results: list[CVSSMetric] = []
    for key in _METRIC_KEYS:
        for entry in metrics_obj.get(key, []):
            data = entry.get("cvssData", {})
            results.append(
                CVSSMetric(
                    version=str(data.get("version", key)),
                    source=entry.get("source"),
                    base_score=data.get("baseScore"),
                    # CVSS v2 puts severity at the metric level, v3 in cvssData.
                    base_severity=data.get("baseSeverity") or entry.get("baseSeverity"),
                    vector=data.get("vectorString"),
                )
            )
    return results


def _parse_cwes(cve: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value not in cwes:
                cwes.append(str(value))
    return cwes


def parse_cve(cve: dict[str, Any]) -> CVERecord:
    """Normalise one NVD ``cve`` object into a :class:`CVERecord`."""
    return CVERecord(
        cve_id=str(cve.get("id", "")),
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        status=cve.get("vulnStatus"),
        description=_english_description(cve),
        cvss=_parse_metrics(cve),
        cwes=_parse_cwes(cve),
        references=[str(ref.get("url")) for ref in cve.get("references", []) if ref.get("url")],
        in_kev=bool(cve.get("cisaExploitAdd")),
    )


def parse_cve_response(payload: dict[str, Any]) -> list[CVERecord]:
    """Extract all CVE records from a raw NVD 2.0 response."""
    return [
        parse_cve(item["cve"])
        for item in payload.get("vulnerabilities", [])
        if isinstance(item, dict) and "cve" in item
    ]


class NVDClient:
    """Query the NVD CVE 2.0 API with caching and rate limiting."""

    def __init__(self, http: IntelHTTP, *, base_url: str, api_key: str = "", ttl_seconds: int = 0):
        self._http = http
        self._base_url = base_url
        self._api_key = api_key
        self._ttl = ttl_seconds

    def _headers(self) -> dict[str, str] | None:
        return {"apiKey": self._api_key} if self._api_key else None

    def lookup_cve(self, cve_id: str) -> CVERecord:
        """Look up a single CVE by id."""
        normalised = validate_cve_id(cve_id)
        payload = self._http.get_json(
            self._base_url,
            params={"cveId": normalised},
            headers=self._headers(),
            cache_key=f"nvd:cve:{normalised}",
            ttl_seconds=self._ttl,
        )
        records = parse_cve_response(payload)
        if not records:
            raise ValidationFailedError(f"no NVD record found for {normalised}")
        return records[0]

    def search_cves(self, keyword: str, *, limit: int = 10) -> CVESearchResult:
        """Search CVEs by keyword (most-recent first is not guaranteed by NVD)."""
        keyword = keyword.strip()
        if not keyword:
            raise ValidationFailedError("keyword must not be empty")
        capped = max(1, min(limit, 50))
        payload = self._http.get_json(
            self._base_url,
            params={"keywordSearch": keyword, "resultsPerPage": capped},
            headers=self._headers(),
            cache_key=f"nvd:search:{keyword.lower()}:{capped}",
            ttl_seconds=self._ttl,
        )
        records = parse_cve_response(payload)
        return CVESearchResult(
            query=keyword,
            total=int(payload.get("totalResults", len(records))),
            returned=len(records),
            cves=records,
        )
