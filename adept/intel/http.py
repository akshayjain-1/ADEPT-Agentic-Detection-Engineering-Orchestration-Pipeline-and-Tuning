"""Shared HTTP helper for threat-intel sources.

Centralises the cross-cutting concerns for every outbound intel request:

* **SSRF guard** — only hosts on the configured allowlist may be fetched, and
  only over ``http``/``https``. This matters because some sources (RSS feeds)
  are user-configurable.
* **Caching** — responses are cached to disk with a TTL so repeated lookups are
  fast and the system tolerates upstream outages and rate limits.
* **Rate limiting** — an optional blocking token-bucket throttles a source
  (used for the NVD API).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

import httpx

from adept.shared.cache import DiskCache
from adept.shared.errors import SecurityError, ToolExecutionError
from adept.shared.ratelimit import SyncRateLimiter

_ALLOWED_SCHEMES = {"http", "https"}

#: Hard cap on a single streamed intel download, to bound memory use if an
#: upstream misbehaves. The largest expected body is the MITRE ATT&CK STIX
#: bundle (tens of MB), so 256 MiB leaves ample headroom.
_MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024


def host_allowed(url: str, allowed_domains: set[str]) -> bool:
    """Return whether ``url``'s scheme and host are permitted."""
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES:
        return False
    host = parts.hostname
    return host is not None and host in allowed_domains


class IntelHTTP:
    """A cache-and-allowlist-aware synchronous HTTP client for intel sources."""

    def __init__(
        self,
        *,
        allowed_domains: set[str],
        cache: DiskCache,
        rate_limiter: SyncRateLimiter | None = None,
        client: httpx.Client | None = None,
        timeout: float = 20.0,
    ) -> None:
        self._allowed = allowed_domains
        self._cache = cache
        self._limiter = rate_limiter
        # Redirects are disabled: the SSRF guard validates the requested host,
        # but cannot vet a redirect target, so a permitted host could otherwise
        # bounce us to an arbitrary one. The intel endpoints serve 200 directly.
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)

    def _guard(self, url: str) -> None:
        if not host_allowed(url, self._allowed):
            raise SecurityError(
                f"refusing to fetch {url!r}: host not on the intel allowlist "
                f"({sorted(self._allowed)})"
            )

    def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache_key: str | None = None,
        ttl_seconds: int = 0,
    ) -> Any:
        """GET ``url`` and parse JSON, honouring the allowlist, cache and limiter."""
        self._guard(url)
        if cache_key and ttl_seconds > 0:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        if self._limiter is not None:
            self._limiter.acquire()
        try:
            response = self._client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            raise ToolExecutionError(f"intel request to {url} failed: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ToolExecutionError(
                f"intel response from {url} was not valid JSON: {exc}"
            ) from exc

        if cache_key and ttl_seconds > 0:
            self._cache.set(cache_key, data, ttl_seconds)
        return data

    def download_text(self, url: str, *, max_bytes: int = _MAX_DOWNLOAD_BYTES) -> str:
        """GET ``url`` and return the body as text (allowlist-guarded).

        The body is streamed and the request is aborted once it exceeds
        ``max_bytes`` so a compromised or misbehaving upstream cannot exhaust
        memory.
        """
        self._guard(url)
        if self._limiter is not None:
            self._limiter.acquire()
        try:
            with self._client.stream("GET", url) as response:
                response.raise_for_status()
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ToolExecutionError(
                            f"intel download from {url} exceeded the {max_bytes}-byte cap"
                        )
                    chunks.append(chunk)
                encoding = response.encoding or "utf-8"
        except httpx.HTTPError as exc:
            raise ToolExecutionError(f"intel download from {url} failed: {exc}") from exc
        return b"".join(chunks).decode(encoding, errors="replace")

    def close(self) -> None:
        self._client.close()
