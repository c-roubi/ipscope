"""Base class every data source plugin inherits from."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from ipscope.models import DomainRecord
from ipscope.ratelimit import RateLimiter


class SourceError(Exception):
    """A source failed for this IP."""


class QuotaExceeded(SourceError):
    """The source's API quota is used up. The engine stops using the source."""


class KeyRejected(SourceError):
    """Every configured API key was rejected. The engine stops using the source."""


class RateLimited(SourceError):
    """Still rate-limited after all retries (often a used-up quota)."""


class _Retryable(Exception):
    pass


@dataclass
class SourceContext:
    session: aiohttp.ClientSession | None
    timeout: float = 15.0
    retries: int = 2
    tls_ports: list[int] = field(default_factory=lambda: [443])
    keys: dict[str, list[str]] = field(default_factory=dict)  # source name -> API keys


class Source(ABC):
    name: str = ""
    description: str = ""
    rate: float = 1.0           # max requests per second (0 = unlimited)
    active: bool = False        # True if it connects to the target itself
    key_env: str | None = None  # env var that can hold API key(s), comma-separated
    requires_key: bool = False  # skipped entirely when no key is configured
    max_pages: int = 5          # pagination cap per IP
    backoff: float = 1.0        # base seconds for exponential backoff

    def __init__(self, ctx: SourceContext):
        self.ctx = ctx
        self.limiter = RateLimiter(self.rate)
        keys = ctx.keys.get(self.name)
        if keys is None and self.key_env:
            keys = [k.strip() for k in os.environ.get(self.key_env, "").split(",") if k.strip()]
        self.keys: list[str] = list(keys or [])
        self._key_idx = 0

    # ---------- keys ----------

    @property
    def api_key(self) -> str | None:
        return self.keys[self._key_idx] if self.keys else None

    @property
    def available(self) -> bool:
        return bool(self.keys) or not self.requires_key

    def rotate_key(self, failed: str | None) -> bool:
        """Move to the next key. Returns False when no fresh key is left.

        `failed` is the key that failed; if another task already rotated past it,
        we just retry with the current key.
        """
        if failed is None or not self.keys:
            return False
        if self.api_key != failed:
            return True
        if self._key_idx + 1 < len(self.keys):
            self._key_idx += 1
            return True
        return False

    def _auth(self, key: str) -> tuple[dict[str, str], dict[str, str]]:
        """Override: return (extra query params, extra headers) for this key."""
        return {}, {}

    # ---------- lookup ----------

    async def lookup(self, ip: str) -> list[DomainRecord]:
        return await self._lookup(ip)

    @abstractmethod
    async def _lookup(self, ip: str) -> list[DomainRecord]:
        ...

    async def _fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        as_json: bool = False,
    ) -> Any:
        """HTTP request with rate limiting, key rotation, retries and backoff.

        Returns None on 404 (most APIs use it for "no data on this IP").
        """
        if self.ctx.session is None:
            raise SourceError("no HTTP session")
        last: Exception | None = None
        attempt = 0
        while attempt <= self.ctx.retries:
            await self.limiter.acquire()
            key = self.api_key
            p, h = dict(params or {}), dict(headers or {})
            if key:
                ap, ah = self._auth(key)
                p.update(ap)
                h.update(ah)
            try:
                async with self.ctx.session.request(
                    method, url,
                    params=p or None, headers=h or None, json=json_body,
                    timeout=aiohttp.ClientTimeout(total=self.ctx.timeout),
                ) as resp:
                    if resp.status in (401, 403) and key:
                        if self.rotate_key(key):
                            continue
                        raise KeyRejected(f"HTTP {resp.status}: API key rejected")
                    if resp.status == 429:
                        if self.rotate_key(key) and len(self.keys) > 1:
                            continue
                        raise _Retryable("HTTP 429 rate limited")
                    if resp.status >= 500:
                        raise _Retryable(f"HTTP {resp.status}")
                    if resp.status == 404:
                        return None
                    if resp.status >= 400:
                        raise SourceError(f"HTTP {resp.status}")
                    if as_json:
                        return await resp.json(content_type=None)
                    return await resp.text()
            except (aiohttp.ClientError, asyncio.TimeoutError, _Retryable) as e:
                last = e
                if attempt < self.ctx.retries:
                    await asyncio.sleep(self.backoff * (2 ** attempt))
                attempt += 1
        if isinstance(last, _Retryable) and "429" in str(last):
            raise RateLimited("HTTP 429: rate limited / quota used up")
        raise SourceError(f"request failed: {last or 'unknown error'}")
