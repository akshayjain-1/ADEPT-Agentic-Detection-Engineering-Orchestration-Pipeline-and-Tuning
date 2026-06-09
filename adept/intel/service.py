"""Composition root for the threat-intel clients.

:class:`IntelService` wires the shared HTTP helper (allowlist + cache + rate
limit) to the four source clients (NVD, KEV, ATT&CK, news) from a
:class:`~adept.config.settings.Settings` instance. The MCP intel tools depend on
this single object.
"""

from __future__ import annotations

from dataclasses import dataclass

from adept.config.settings import Settings
from adept.intel.attack import AttackClient
from adept.intel.http import IntelHTTP
from adept.intel.kev import KEVClient
from adept.intel.news import NewsClient, feed_hosts
from adept.intel.nvd import NVDClient
from adept.shared.cache import DiskCache
from adept.shared.ratelimit import SyncRateLimiter


@dataclass(slots=True)
class IntelService:
    """Bundle of configured threat-intel clients."""

    nvd: NVDClient
    kev: KEVClient
    attack: AttackClient
    news: NewsClient
    _https: tuple[IntelHTTP, ...]

    @classmethod
    def from_settings(cls, settings: Settings) -> IntelService:
        intel = settings.intel
        data_dir = settings.ensure_data_dir()
        cache = DiskCache(data_dir / "cache", namespace="intel")

        # RSS feeds are operator-configured, so their hosts are implicitly
        # trusted in addition to the explicit API allowlist.
        allowed = set(intel.allowed_domains) | feed_hosts(intel.rss_feeds)

        # NVD throttling: refill at the per-minute budget (converted to
        # tokens/second) but allow a burst up to a full minute's worth so a
        # single lookup never has to wait for the slow sub-1/s refill.
        per_minute = max(intel.nvd_rate_per_minute, 1.0)
        nvd_limiter = SyncRateLimiter(rate=per_minute / 60.0, capacity=per_minute)
        nvd_http = IntelHTTP(allowed_domains=allowed, cache=cache, rate_limiter=nvd_limiter)
        shared_http = IntelHTTP(allowed_domains=allowed, cache=cache)

        return cls(
            nvd=NVDClient(
                nvd_http,
                base_url=intel.nvd_url,
                api_key=intel.nvd_api_key,
                ttl_seconds=intel.cache_ttl_seconds,
            ),
            kev=KEVClient(shared_http, url=intel.kev_url, ttl_seconds=intel.cache_ttl_seconds),
            attack=AttackClient(
                shared_http,
                stix_url=intel.attack_stix_url,
                cache_file=data_dir / "attack" / "enterprise-attack.json",
                ttl_seconds=intel.attack_cache_ttl_seconds,
            ),
            news=NewsClient(
                shared_http,
                feeds=intel.rss_feeds,
                ttl_seconds=intel.cache_ttl_seconds,
            ),
            _https=(nvd_http, shared_http),
        )

    def close(self) -> None:
        """Close the underlying HTTP clients."""
        for http in self._https:
            http.close()
