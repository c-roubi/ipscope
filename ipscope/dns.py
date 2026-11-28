"""DNS helpers: forward resolution and status classification."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections import OrderedDict

from ipscope.models import Status

try:
    import dns.asyncresolver
    import dns.exception
    import dns.name
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None


async def resolve(domain: str, timeout: float = 5.0) -> list[str]:
    """Return all A/AAAA addresses for a domain via the OS (empty list if none)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(domain, None, type=socket.SOCK_STREAM), timeout
        )
    except (socket.gaierror, TimeoutError, OSError, UnicodeError):
        return []
    return sorted({info[4][0] for info in infos})


def classify(ip: str, resolved: list[str] | None) -> Status:
    if resolved is None:
        return Status.UNKNOWN  # lookup failed (timeout / SERVFAIL): don't call it dead
    if not resolved:
        return Status.DEAD
    target = ipaddress.ip_address(ip)
    for addr in resolved:
        try:
            if ipaddress.ip_address(addr.split("%")[0]) == target:
                return Status.ACTIVE
        except ValueError:
            continue
    return Status.HISTORICAL


class AsyncResolver:
    """High-concurrency resolver for validating many domains.

    Uses dnspython's asyncio resolver (real parallel UDP queries) instead of the OS
    resolver, which runs in a small thread pool. Answers are cached for the whole
    scan because the same domain often shows up on several IPs.

    resolve() returns a list of addresses, [] if the name doesn't exist / has no
    A or AAAA records, or None if the lookup itself failed.
    """

    def __init__(self, timeout: float = 5.0, concurrency: int = 200, cache_size: int = 200_000):
        self.timeout = timeout
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self.cache_size = cache_size
        self._cache: OrderedDict[str, list[str]] = OrderedDict()
        self._inflight: dict[str, asyncio.Future] = {}
        self._r = None
        if dns is not None:
            try:
                self._r = dns.asyncresolver.Resolver()
                self._r.timeout = min(2.0, timeout)  # per-server try
                self._r.lifetime = timeout
            except Exception:
                self._r = None

    async def resolve(self, domain: str) -> list[str] | None:
        hit = self._cache.get(domain)
        if hit is not None:
            self._cache.move_to_end(domain)
            return hit
        fut = self._inflight.get(domain)
        if fut is not None:  # same domain already being resolved by another task
            return await asyncio.shield(fut)
        fut = asyncio.get_running_loop().create_future()
        self._inflight[domain] = fut
        try:
            async with self.sem:
                res = await self._lookup(domain)
            if res is not None:
                self._cache[domain] = res
                if len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)
            fut.set_result(res)
            return res
        except BaseException as e:
            if not fut.done():
                fut.set_result(None)
            if isinstance(e, Exception):
                return None
            raise
        finally:
            self._inflight.pop(domain, None)

    async def _lookup(self, domain: str) -> list[str] | None:
        if self._r is None:
            return await resolve(domain, self.timeout) or []
        a, aaaa = await asyncio.gather(self._query(domain, "A"), self._query(domain, "AAAA"))
        if a is None and aaaa is None:
            return None
        return sorted(set((a or []) + (aaaa or [])))

    async def _query(self, name: str, rtype: str) -> list[str] | None:
        try:
            ans = await self._r.resolve(name, rtype, search=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN, dns.name.NameTooLong,
                dns.name.LabelTooLong, dns.name.EmptyLabel):
            return []
        except (dns.exception.DNSException, OSError):
            return None  # timeout, SERVFAIL, no nameservers
        return [r.to_text() for r in ans]
