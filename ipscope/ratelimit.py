"""Per-source async rate limiting."""

from __future__ import annotations

import asyncio


class RateLimiter:
    """Spaces out calls so at most `rate` requests/second are made.

    rate <= 0 disables limiting.
    """

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self) -> None:
        if not self.interval:
            return
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = loop.time()
            self._next = now + self.interval
