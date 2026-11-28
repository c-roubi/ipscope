"""Subdomain lookup: domain -> known subdomains, merged from several free sources.

    ipscope subdomains example.com -V -o subs.csv
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from ipscope import __version__
from ipscope.models import normalize_domain
from ipscope.sources.apis import _raise_for_message
from ipscope.sources.base import Source, SourceContext, SourceError


def _under(name: str | None, domain: str) -> str | None:
    d = normalize_domain(name)
    if d and (d == domain or d.endswith("." + domain)):
        return d
    return None


class SubSource(Source):
    """A source that maps a domain to subdomains (reuses rate limiting, retries, keys)."""

    async def _lookup(self, ip: str):  # not used for subdomain sources
        raise NotImplementedError

    async def subdomains(self, domain: str) -> list[str]:
        raise NotImplementedError


class DNSRiftSubs(SubSource):
    name = "dnsrift"
    description = "DNSRift subdomain API (free, no key)"
    key_env = "IPSCOPE_DNSRIFT_KEY"
    URL = "https://api.dnsrift.net/subdomain-lookup"

    def _auth(self, key):
        return {"key": key}, {}

    async def subdomains(self, domain: str) -> list[str]:
        return self.parse(await self._fetch(self.URL, params={"domain": domain}, as_json=True), domain)

    @staticmethod
    def parse(data: Any, domain: str) -> list[str]:
        if not isinstance(data, dict):
            return []
        if data.get("message") and not data.get("subdomains"):
            msg = str(data["message"])
            if "no " in msg.lower() or "not found" in msg.lower():
                return []
            _raise_for_message(msg)
        return [d for d in (_under(x, domain) for x in data.get("subdomains") or []) if d]


class THCSubs(SubSource):
    name = "thc"
    description = "ip.thc.org subdomain API (free, no key)"
    rate = 0.5
    max_pages = 10
    URL = "https://ip.thc.org/api/v1/lookup/subdomains"

    async def subdomains(self, domain: str) -> list[str]:
        out, state = [], None
        for _ in range(self.max_pages):
            body = {"domain": domain, "limit": 200}
            if state:
                body["page_state"] = state
            data = await self._fetch(self.URL, method="POST", json_body=body, as_json=True)
            names, state = self.parse(data, domain)
            out += names
            if not state:
                break
        return out

    @staticmethod
    def parse(data: Any, domain: str) -> tuple[list[str], str | None]:
        if not isinstance(data, dict):
            return [], None
        names = [_under(d.get("domain"), domain) for d in data.get("domains") or [] if isinstance(d, dict)]
        return [n for n in names if n], data.get("next_page_state") or None


class OTXSubs(SubSource):
    name = "otx"
    description = "AlienVault OTX passive DNS for the domain (free)"
    key_env = "IPSCOPE_OTX_KEY"
    URL = "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"

    def _auth(self, key):
        return {}, {"X-OTX-API-KEY": key}

    async def subdomains(self, domain: str) -> list[str]:
        data = await self._fetch(self.URL.format(d=domain), as_json=True)
        if not isinstance(data, dict):
            return []
        return [n for n in (_under(e.get("hostname"), domain) for e in data.get("passive_dns") or []) if n]


class CrtShSubs(SubSource):
    name = "crtsh"
    description = "crt.sh certificate transparency logs (free; slow at times)"
    rate = 0.5
    URL = "https://crt.sh/"

    async def subdomains(self, domain: str) -> list[str]:
        data = await self._fetch(self.URL, params={"q": f"%.{domain}", "output": "json"}, as_json=True)
        return self.parse(data, domain)

    @staticmethod
    def parse(data: Any, domain: str) -> list[str]:
        out = []
        for row in data or []:
            if isinstance(row, dict):
                for n in str(row.get("name_value", "")).split("\n"):
                    d = _under(n, domain)
                    if d:
                        out.append(d)
        return out


class RapidDNSSubs(SubSource):
    name = "rapiddns"
    description = "RapidDNS subdomain search (Pro key required)"
    key_env = "IPSCOPE_RAPIDDNS_KEY"
    requires_key = True
    max_pages = 10
    URL = "https://rapiddns.io/api/search/{q}"

    def _auth(self, key):
        return {}, {"X-API-KEY": key}

    async def subdomains(self, domain: str) -> list[str]:
        from ipscope.sources.apis import RapidDNS
        out = []
        for page in range(1, self.max_pages + 1):
            data = await self._fetch(self.URL.format(q=domain), as_json=True,
                                     params={"search_type": "subdomain", "page": str(page), "pagesize": "500"})
            recs, total = RapidDNS.parse(data, self.name)
            out += [n for n in (_under(r.domain, domain) for r in recs) if n]
            if not recs or page * 500 >= total:
                break
        return out


class LocalSubs(SubSource):
    name = "local"
    description = "Your local index"
    rate = 0

    @property
    def available(self) -> bool:
        from ipscope.index import LocalIndex
        return LocalIndex.has_data()

    async def subdomains(self, domain: str) -> list[str]:
        from ipscope.index import LocalIndex
        with LocalIndex() as idx:
            rows = idx.db.execute(
                "SELECT name FROM names WHERE name = ? OR name LIKE ? ESCAPE '\\'",
                (domain, "%." + domain.replace("%", "\\%").replace("_", "\\_")),
            ).fetchall()
        return [r[0] for r in rows]


SUB_REGISTRY: dict[str, type[SubSource]] = {
    c.name: c for c in (LocalSubs, DNSRiftSubs, THCSubs, OTXSubs, CrtShSubs, RapidDNSSubs)
}
DEFAULT_SUB_SOURCES = ["local", "dnsrift", "thc", "otx", "crtsh", "rapiddns"]


@dataclass
class SubResult:
    domain: str
    names: dict[str, set[str]] = field(default_factory=dict)      # subdomain -> sources
    errors: dict[str, str] = field(default_factory=dict)
    resolved: dict[str, list[str] | None] = field(default_factory=dict)


async def find_subdomains(
    domains: list[str],
    sources: list[str] | None = None,
    keys: dict[str, list[str]] | None = None,
    validate: bool = False,
    timeout: float = 30.0,
    registry: dict[str, type[SubSource]] | None = None,
    on_done: Callable[[SubResult], None] | None = None,
) -> tuple[list[SubResult], list[str]]:
    """Returns (results, skipped sources)."""
    reg = registry or SUB_REGISTRY
    names = sources or DEFAULT_SUB_SOURCES
    headers = {"User-Agent": f"IPScope/{__version__}"}
    async with aiohttp.ClientSession(headers=headers, trust_env=True) as session:
        ctx = SourceContext(session, timeout=timeout, retries=2, keys=keys or {})
        built = [reg[n](ctx) for n in names if n in reg]
        srcs = [s for s in built if s.available]
        skipped = [s.name for s in built if not s.available]
        resolver = None
        if validate:
            from ipscope.dns import AsyncResolver
            resolver = AsyncResolver(timeout=5, concurrency=200)

        results = []
        for raw in domains:
            domain = normalize_domain(raw.strip().split("://")[-1].split("/")[0])
            if not domain:
                continue
            res = SubResult(domain)
            outs = await asyncio.gather(*(s.subdomains(domain) for s in srcs), return_exceptions=True)
            for s, out in zip(srcs, outs):
                if isinstance(out, Exception):
                    res.errors[s.name] = str(out) or type(out).__name__
                    continue
                for n in out:
                    res.names.setdefault(n, set()).add(s.name)
            if resolver and res.names:
                answers = await asyncio.gather(*(resolver.resolve(n) for n in res.names))
                res.resolved = dict(zip(res.names, answers))
            results.append(res)
            if on_done:
                on_done(res)
    return results, skipped
