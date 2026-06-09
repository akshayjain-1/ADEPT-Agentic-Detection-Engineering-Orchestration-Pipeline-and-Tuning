"""Security-news aggregation from RSS/Atom feeds.

Feeds are fetched through :class:`IntelHTTP` (so the allowlist, timeout and cache
all apply) and parsed with ``feedparser``. The heavy ``feedparser`` import is
deferred to first use.
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

from adept.intel.http import IntelHTTP
from adept.intel.models import NewsItem, NewsResult
from adept.shared.logging import get_logger

log = get_logger(__name__)


def feed_hosts(feeds: list[str]) -> set[str]:
    """Return the set of hostnames referenced by the configured feeds."""
    hosts: set[str] = set()
    for url in feeds:
        host = urlsplit(url).hostname
        if host:
            hosts.add(host)
    return hosts


def _parse_with_timestamps(text: str, source_hint: str) -> list[tuple[NewsItem, float]]:
    """Parse raw feed ``text`` into ``(item, sort_epoch)`` tuples."""
    import feedparser

    parsed = feedparser.parse(text)
    source = str(parsed.feed.get("title", "")) or source_hint
    results: list[tuple[NewsItem, float]] = []
    for entry in parsed.entries:
        item = NewsItem(
            title=str(entry.get("title", "")),
            link=str(entry.get("link", "")),
            published=str(entry.get("published", "") or entry.get("updated", "")),
            summary=str(entry.get("summary", "")),
            source=source,
        )
        struct = entry.get("published_parsed") or entry.get("updated_parsed")
        ts = time.mktime(struct) if struct else 0.0
        results.append((item, ts))
    return results


def parse_feed(text: str, source_hint: str = "") -> list[NewsItem]:
    """Parse raw feed ``text`` into :class:`NewsItem` objects (newest first)."""
    pairs = _parse_with_timestamps(text, source_hint)
    pairs.sort(key=lambda pair: pair[1], reverse=True)
    return [item for item, _ in pairs]


class NewsClient:
    """Fetch and merge security-news items from configured RSS/Atom feeds."""

    def __init__(self, http: IntelHTTP, *, feeds: list[str], ttl_seconds: int = 0):
        self._http = http
        self._feeds = feeds
        self._ttl = ttl_seconds

    def fetch_security_news(self, *, limit: int = 20) -> NewsResult:
        """Return the most recent news items across all configured feeds."""
        dated: list[tuple[NewsItem, float]] = []
        for url in self._feeds:
            try:
                text = self._http.download_text(url)
            except Exception as exc:  # one broken feed must not sink the rest
                log.warning("intel.news.feed_failed", feed=url, error=str(exc))
                continue
            dated.extend(_parse_with_timestamps(text, urlsplit(url).hostname or url))

        dated.sort(key=lambda pair: pair[1], reverse=True)
        items = [item for item, _ in dated[: max(1, limit)]]
        return NewsResult(total=len(dated), items=items)
