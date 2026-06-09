"""Mapping between ADEPT SIEM identifiers and pySigma conversion targets.

These were verified against ``sigma list targets`` for sigma-cli 3.x: the ``-t``
value is the *backend output format name*, which is NOT the same as the backend
package name (e.g. the Elasticsearch backend's primary target is ``lucene``).
"""

from __future__ import annotations

#: SIEM id -> default pySigma conversion target (the ``sigma convert -t`` value).
SIEM_CONVERTER_TARGETS: dict[str, str] = {
    "elk": "lucene",
    "opensearch": "opensearch_lucene",
    "splunk": "splunk",
}

#: SIEM id -> human-readable query language (for prompts and packets).
SIEM_QUERY_LANGUAGE: dict[str, str] = {
    "elk": "Elasticsearch Lucene",
    "opensearch": "OpenSearch Lucene",
    "splunk": "SPL",
}

#: All SIEM identifiers ADEPT understands.
SIEM_IDS: tuple[str, ...] = ("elk", "opensearch", "splunk")


def converter_target(siem_id: str) -> str:
    """Return the pySigma target for a SIEM id, or raise ``KeyError``."""
    return SIEM_CONVERTER_TARGETS[siem_id]
