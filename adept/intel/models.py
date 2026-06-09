"""Pydantic models for threat-intelligence results.

These normalise the verbose upstream payloads (NVD CVE 2.0, CISA KEV, ATT&CK
STIX, RSS) into compact, typed shapes for the agent and the human reviewer.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CVSSMetric(BaseModel):
    """A single CVSS metric extracted from an NVD record."""

    version: str
    source: str | None = None
    base_score: float | None = None
    base_severity: str | None = None
    vector: str | None = None


class CVERecord(BaseModel):
    """A normalised NVD CVE record."""

    cve_id: str
    published: str | None = None
    last_modified: str | None = None
    status: str | None = None
    description: str = ""
    cvss: list[CVSSMetric] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    in_kev: bool = False

    @property
    def top_severity(self) -> str | None:
        for metric in self.cvss:
            if metric.base_severity:
                return metric.base_severity
        return None


class CVESearchResult(BaseModel):
    """A page of CVE search results."""

    query: str
    total: int
    returned: int
    cves: list[CVERecord] = Field(default_factory=list)


class KEVEntry(BaseModel):
    """A single CISA Known Exploited Vulnerability."""

    cve_id: str
    vendor_project: str = ""
    product: str = ""
    name: str = ""
    date_added: str = ""
    due_date: str = ""
    short_description: str = ""
    required_action: str = ""
    known_ransomware: str = ""


class KEVResult(BaseModel):
    """A filtered view of the CISA KEV catalogue."""

    catalog_version: str = ""
    date_released: str = ""
    total: int = 0
    returned: int = 0
    entries: list[KEVEntry] = Field(default_factory=list)


class AttackTechnique(BaseModel):
    """A normalised MITRE ATT&CK (enterprise) technique."""

    attack_id: str
    name: str = ""
    description: str = ""
    is_subtechnique: bool = False
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    detection: str = ""
    url: str = ""


class NewsItem(BaseModel):
    """A single security-news entry from an RSS/Atom feed."""

    title: str = ""
    link: str = ""
    published: str = ""
    summary: str = ""
    source: str = ""


class NewsResult(BaseModel):
    """A collection of recent security-news items."""

    total: int = 0
    items: list[NewsItem] = Field(default_factory=list)
