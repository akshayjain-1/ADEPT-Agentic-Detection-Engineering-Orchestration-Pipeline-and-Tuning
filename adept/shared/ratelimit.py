"""An asyncio token-bucket rate limiter.

Throttles outbound calls to external services (e.g. the NVD API, which is rate
limited) so ADEPT stays a well-behaved API citizen.
"""

from __future__ import annotations

import asyncio
import threading
import time


class AsyncRateLimiter:
    """A token-bucket limiter for async code.

    Args:
        rate: Tokens refilled per second (the sustained request rate).
        capacity: Maximum bucket size (the burst allowance). Defaults to
            ``rate`` (i.e. a burst of roughly one second of traffic).
    """

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate
        self._capacity = capacity if capacity is not None else rate
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        """Block until ``tokens`` are available, then consume them."""
        if tokens > self._capacity:
            raise ValueError("requested tokens exceed bucket capacity")
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                await asyncio.sleep(deficit / self._rate)


class SyncRateLimiter:
    """A thread-safe, blocking token-bucket limiter for synchronous code.

    The MCP tools and SIEM/intel clients run synchronously, so they cannot use
    :class:`AsyncRateLimiter`. This sibling provides the same token-bucket
    behaviour with a blocking :meth:`acquire`.

    Args:
        rate: Tokens refilled per second (the sustained request rate).
        capacity: Maximum bucket size (the burst allowance). Defaults to
            ``rate``.
    """

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate
        self._capacity = capacity if capacity is not None else rate
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        """Block until ``tokens`` are available, then consume them."""
        if tokens > self._capacity:
            raise ValueError("requested tokens exceed bucket capacity")
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
            time.sleep(deficit / self._rate)
