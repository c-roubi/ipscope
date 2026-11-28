"""IP -> ASN via Team Cymru's DNS service, and ASN -> prefixes via RIPEstat.

Both are free and need no key. Team Cymru answers TXT queries such as
    4.3.2.1.origin.asn.cymru.com  ->  "13335 | 1.2.3.0/24 | US | arin | 2010-07-14"
    AS13335.asn.cymru.com         ->  "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import aiohttp

from ipscope.enrich.providers import detect_provider

try:
    import dns.asyncresolver
    import dns.exception
except ImportError:  # optional at runtime
    dns = None

RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"


def cymru_origin_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(str(addr).split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_origin(records: list[str]) -> dict:
    """Pick the most specific prefix among the TXT answers."""
    best: dict = {}
    best_len = -1
    for txt in records:
        parts = [p.strip() for p in txt.split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        try:
            asn = int(parts[0].split()[0])
            plen = ipaddress.ip_network(parts[1], strict=False).prefixlen
        except ValueError:
            continue
        if plen > best_len:
            best_len = plen
            best = {
                "asn": asn,
                "prefix": parts[1],
                "country": parts[2] or None,
                "registry": parts[3] if len(parts) > 3 and parts[3] else None,
            }
    return best


def parse_asname(records: list[str]) -> str | None:
    for txt in records:
        parts = [p.strip() for p in txt.split("|")]
        if len(parts) >= 5 and parts[4]:
            return parts[4]
    return None


def parse_ripestat(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return []
    prefixes = ((data.get("data") or {}).get("prefixes")) or []
    return [p["prefix"] for p in prefixes if isinstance(p, dict) and p.get("prefix")]


class ASNResolver:
    """Looks up ASN + provider info for IPs; caches AS names."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._names: dict[int, str | None] = {}
        self._resolver = None
        if dns is not None:
            try:
                self._resolver = dns.asyncresolver.Resolver()
            except Exception:  # no resolver config on this machine
                self._resolver = None

    async def _txt(self, qname: str) -> list[str]:
        if self._resolver is None:
            return []
        try:
            ans = await self._resolver.resolve(qname, "TXT", lifetime=self.timeout)
        except (dns.exception.DNSException, OSError, asyncio.TimeoutError):
            return []
        return [b"".join(r.strings).decode("utf-8", "ignore") for r in ans]

    async def lookup(self, ip: str) -> dict:
        info = parse_origin(await self._txt(cymru_origin_name(ip)))
        asn = info.get("asn")
        if asn is not None:
            if asn not in self._names:
                self._names[asn] = parse_asname(await self._txt(f"AS{asn}.asn.cymru.com"))
            info["as_name"] = self._names[asn]
        provider, category = detect_provider(ip, asn, info.get("as_name"))
        info["provider"] = provider
        info["category"] = category
        return info


async def asn_prefixes(session: aiohttp.ClientSession, asn: int, timeout: float = 20.0) -> list[str]:
    async with session.get(
        RIPESTAT_URL, params={"resource": f"AS{asn}"},
        timeout=aiohttp.ClientTimeout(total=timeout),
    ) as resp:
        if resp.status != 200:
            raise RuntimeError(f"RIPEstat HTTP {resp.status}")
        return parse_ripestat(await resp.json(content_type=None))
