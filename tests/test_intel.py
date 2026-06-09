"""Unit tests for the threat-intel clients.

All network access is faked with ``httpx.MockTransport`` and canned payloads
shaped like the real NVD / CISA KEV / ATT&CK / RSS responses, so these tests are
deterministic and offline.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from adept.intel.attack import parse_technique, validate_attack_id
from adept.intel.http import IntelHTTP, host_allowed
from adept.intel.kev import KEVClient, parse_kev_entry
from adept.intel.news import feed_hosts, parse_feed
from adept.intel.nvd import NVDClient, parse_cve, validate_cve_id
from adept.shared.cache import DiskCache
from adept.shared.errors import SecurityError, ToolExecutionError, ValidationFailedError

# ---------------------------------------------------------------------------
# Canned payloads
# ---------------------------------------------------------------------------
NVD_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-11-07T03:39:18.323",
                "vulnStatus": "Analyzed",
                "cisaExploitAdd": "2021-12-10",
                "descriptions": [
                    {"lang": "es", "value": "Apache Log4j2 (en espanol)"},
                    {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect..."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            },
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "baseSeverity": "HIGH",
                            "cvssData": {"version": "2.0", "baseScore": 9.3},
                        }
                    ],
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-502"}]},
                    {"description": [{"lang": "en", "value": "CWE-400"}]},
                ],
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                    {"url": "https://www.cisa.gov/"},
                ],
            }
        }
    ],
}

KEV_CATALOG = {
    "catalogVersion": "2025.01.01",
    "dateReleased": "2025-01-01T00:00:00.000Z",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 RCE (Log4Shell)",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "shortDescription": "Remote code execution via JNDI lookups.",
            "requiredAction": "Apply updates.",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2020-0001",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget bug",
            "dateAdded": "2020-01-01",
            "dueDate": "2020-01-15",
            "shortDescription": "A different vulnerability.",
            "requiredAction": "Patch.",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}

ATTACK_STIX = {
    "id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22",
    "name": "OS Credential Dumping: LSASS Memory",
    "description": "Adversaries may attempt to access credential material...",
    "x_mitre_is_subtechnique": True,
    "x_mitre_platforms": ["Windows"],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "T1003.001",
            "url": "https://attack.mitre.org/techniques/T1003/001",
        },
        {"source_name": "capec", "url": "https://capec.mitre.org/"},
    ],
}

RSS_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>The Hacker News</title>
    <item>
      <title>Old story</title>
      <link>https://thehackernews.test/old</link>
      <pubDate>Mon, 01 Jan 2024 00:00:00 +0000</pubDate>
      <description>An older item.</description>
    </item>
    <item>
      <title>Fresh story</title>
      <link>https://thehackernews.test/new</link>
      <pubDate>Wed, 01 Jan 2025 00:00:00 +0000</pubDate>
      <description>A newer item.</description>
    </item>
  </channel>
</rss>
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _http(
    tmp_path: Path,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    allowed: set[str],
) -> IntelHTTP:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    cache = DiskCache(tmp_path / "cache", namespace="intel-test")
    return IntelHTTP(allowed_domains=allowed, cache=cache, client=client)


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------
def test_host_allowed_accepts_allowlisted_https() -> None:
    assert host_allowed("https://services.nvd.nist.gov/rest", {"services.nvd.nist.gov"})


def test_host_allowed_rejects_unlisted_host() -> None:
    assert not host_allowed("https://evil.example/", {"services.nvd.nist.gov"})


def test_host_allowed_rejects_non_http_scheme() -> None:
    assert not host_allowed("file:///etc/passwd", {"etc"})
    assert not host_allowed("ftp://services.nvd.nist.gov/x", {"services.nvd.nist.gov"})


def test_get_json_blocks_unlisted_host(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("transport should not be reached for a blocked host")

    http = _http(tmp_path, handler, allowed={"good.test"})
    with pytest.raises(SecurityError):
        http.get_json("https://evil.test/data")


def test_get_json_raises_tool_error_on_http_500(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    http = _http(tmp_path, handler, allowed={"good.test"})
    with pytest.raises(ToolExecutionError):
        http.get_json("https://good.test/data")


def test_get_json_uses_cache(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"ok": True})

    http = _http(tmp_path, handler, allowed={"good.test"})
    first = http.get_json("https://good.test/x", cache_key="k", ttl_seconds=60)
    second = http.get_json("https://good.test/x", cache_key="k", ttl_seconds=60)
    assert first == second == {"ok": True}
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------
def test_validate_cve_id_normalises_and_rejects() -> None:
    assert validate_cve_id("cve-2021-44228") == "CVE-2021-44228"
    with pytest.raises(ValidationFailedError):
        validate_cve_id("not-a-cve")


def test_parse_cve_extracts_all_fields() -> None:
    record = parse_cve(NVD_RESPONSE["vulnerabilities"][0]["cve"])
    assert record.cve_id == "CVE-2021-44228"
    assert record.description.startswith("Apache Log4j2 JNDI")  # English description chosen
    assert record.status == "Analyzed"
    assert record.in_kev is True
    assert record.cwes == ["CWE-502", "CWE-400"]
    assert record.references[0].endswith("security.html")
    assert record.top_severity == "CRITICAL"
    # Both v3.1 and v2 metrics are captured, with v2 severity at the entry level.
    versions = {m.version for m in record.cvss}
    assert versions == {"3.1", "2.0"}
    v2 = next(m for m in record.cvss if m.version == "2.0")
    assert v2.base_severity == "HIGH"


def test_nvd_lookup_cve(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["cveId"] == "CVE-2021-44228"
        return httpx.Response(200, json=NVD_RESPONSE)

    http = _http(tmp_path, handler, allowed={"services.nvd.nist.gov"})
    client = NVDClient(http, base_url="https://services.nvd.nist.gov/rest/json/cves/2.0")
    record = client.lookup_cve("CVE-2021-44228")
    assert record.cve_id == "CVE-2021-44228"
    assert record.top_severity == "CRITICAL"


def test_nvd_lookup_missing_raises(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    http = _http(tmp_path, handler, allowed={"services.nvd.nist.gov"})
    client = NVDClient(http, base_url="https://services.nvd.nist.gov/rest/json/cves/2.0")
    with pytest.raises(ValidationFailedError):
        client.lookup_cve("CVE-1999-0001")


def test_nvd_search_cves(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["keywordSearch"] == "log4j"
        return httpx.Response(200, json=NVD_RESPONSE)

    http = _http(tmp_path, handler, allowed={"services.nvd.nist.gov"})
    client = NVDClient(http, base_url="https://services.nvd.nist.gov/rest/json/cves/2.0")
    result = client.search_cves("log4j", limit=5)
    assert result.total == 1
    assert result.returned == 1
    assert result.cves[0].cve_id == "CVE-2021-44228"


def test_nvd_search_rejects_empty_keyword(tmp_path: Path) -> None:
    http = _http(tmp_path, lambda r: httpx.Response(200, json={}), allowed={"x"})
    client = NVDClient(http, base_url="https://services.nvd.nist.gov/rest/json/cves/2.0")
    with pytest.raises(ValidationFailedError):
        client.search_cves("   ")


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------
def test_parse_kev_entry() -> None:
    entry = parse_kev_entry(KEV_CATALOG["vulnerabilities"][0])
    assert entry.cve_id == "CVE-2021-44228"
    assert entry.product == "Log4j2"
    assert entry.known_ransomware == "Known"


def _kev_client(tmp_path: Path) -> KEVClient:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=KEV_CATALOG)

    http = _http(tmp_path, handler, allowed={"www.cisa.gov"})
    return KEVClient(http, url="https://www.cisa.gov/kev.json")


def test_kev_filter_by_cve(tmp_path: Path) -> None:
    result = _kev_client(tmp_path).get_kev(cve_id="cve-2021-44228")
    assert result.catalog_version == "2025.01.01"
    assert result.returned == 1
    assert result.entries[0].product == "Log4j2"


def test_kev_filter_by_query(tmp_path: Path) -> None:
    result = _kev_client(tmp_path).get_kev(query="widget")
    assert result.returned == 1
    assert result.entries[0].cve_id == "CVE-2020-0001"


def test_kev_no_filter_returns_all(tmp_path: Path) -> None:
    result = _kev_client(tmp_path).get_kev()
    assert result.total == 2
    assert result.returned == 2


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------
def test_validate_attack_id() -> None:
    assert validate_attack_id("t1003") == "T1003"
    assert validate_attack_id("T1003.001") == "T1003.001"
    with pytest.raises(ValidationFailedError):
        validate_attack_id("1003")


def test_parse_technique_maps_fields() -> None:
    tech = parse_technique(ATTACK_STIX, ["Credential Access"])
    assert tech.attack_id == "T1003.001"
    assert tech.is_subtechnique is True
    assert tech.platforms == ["Windows"]
    assert tech.tactics == ["Credential Access"]
    assert tech.url == "https://attack.mitre.org/techniques/T1003/001"
    # Missing optional fields degrade gracefully to empty.
    assert tech.data_sources == []
    assert tech.detection == ""


# ---------------------------------------------------------------------------
# Security news
# ---------------------------------------------------------------------------
def test_feed_hosts_extracts_hostnames() -> None:
    hosts = feed_hosts(["https://a.test/feed", "https://b.test/rss", "not a url"])
    assert hosts == {"a.test", "b.test"}


def test_parse_feed_sorts_newest_first() -> None:
    items = parse_feed(RSS_FEED, "thehackernews.test")
    assert len(items) == 2
    assert items[0].title == "Fresh story"
    assert items[0].source == "The Hacker News"
    assert items[1].title == "Old story"
