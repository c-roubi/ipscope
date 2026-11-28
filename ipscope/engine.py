"""Scan engine.

A fixed pool of workers pulls IPs from the input list, runs every source on each IP,
validates/enriches the domains and hands the finished IPResult to `on_result`.
Memory stays flat for any number of IPs when `collect=False` (results go to the store).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field, fields

import aiohttp

from ipscope import __version__
from ipscope.dns import AsyncResolver, classify
from ipscope.enrich.asn import ASNResolver
from ipscope.enrich.domains import confidence, root_domain
from ipscope.enrich.http_probe import probe
from ipscope.enrich.providers import hosting_type
from ipscope.models import DomainRecord, DomainResult, IPResult, Status
from ipscope.sources import (
    DEFAULT_SOURCES, DEFAULT_TLS_PORTS, REGISTRY, KeyRejected, QuotaExceeded, RateLimited, Source, SourceContext,
)
from ipscope.storage import Store

# consecutive "still rate-limited after retries" failures before a source is switched off
RATE_LIMIT_STRIKES = 3

# order used by first-hit mode: instant / biggest datasets first, slow or narrow ones last
CASCADE_ORDER = [
    "local", "dnsrift", "thc", "internetdb", "otx", "hackertarget", "rapiddns", "networksdb",
    "securitytrails", "virustotal", "shodan", "webscan", "ptr", "tls", "http",
]
_STATUS_RANK = {Status.ACTIVE: 0, Status.UNKNOWN: 1, Status.HISTORICAL: 2, Status.DEAD: 3}


def collapse_to_roots(result: IPResult) -> dict[str, str]:
    """Merge subdomains into one entry per root domain.

    The root keeps the best status of its members (active if any member is active) and
    the union of their sources. Returns root -> member host to use for probing.
    """
    groups: dict[str, list[DomainResult]] = {}
    for d in result.domains.values():
        groups.setdefault(d.root or d.domain, []).append(d)
    merged: dict[str, DomainResult] = {}
    probe_hosts: dict[str, str] = {}
    for root, members in groups.items():
        best = min(members, key=lambda m: (_STATUS_RANK[m.status], m.domain != root,
                                           m.domain != "www." + root, len(m.domain)))
        nd = DomainResult(
            root,
            sources=set().union(*(m.sources for m in members)),
            first_seen=min((m.first_seen for m in members if m.first_seen), default=None),
            last_seen=max((m.last_seen for m in members if m.last_seen), default=None),
            status=best.status,
            resolved_ips=list(best.resolved_ips),
            root=root,
        )
        nd.confidence = confidence(nd)
        merged[root] = nd
        probe_hosts[root] = best.domain
    result.domains = merged
    return probe_hosts


@dataclass
class ScanOptions:
    sources: list[str] = field(default_factory=lambda: list(DEFAULT_SOURCES))
    concurrency: int = 10        # IPs scanned in parallel
    validate: bool = False       # forward-resolve every domain
    dns_concurrency: int = 200   # parallel DNS queries during validation
    timeout: float = 15.0
    retries: int = 2
    tls_ports: list[int] = field(default_factory=lambda: list(DEFAULT_TLS_PORTS))
    use_cache: bool = True
    cache_ttl: float = 24 * 3600  # seconds
    ip_info: bool = True          # ASN / provider / CDN detection (passive DNS query)
    probe: bool = False           # HTTP-probe domains (ACTIVE: contacts the websites)
    probe_concurrency: int = 20
    probe_limit: int = 200        # max domains probed per IP
    local_first: bool = True      # your local index answers first; online sources only for IPs it doesn't know
    first_hit: bool = False       # ask sources one by one; stop at the first that finds domains
    roots_only: bool = False      # keep one entry per root domain (example.com), not every subdomain

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanOptions":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in names})


@dataclass
class ScanStats:
    requests: int = 0
    cache_hits: int = 0
    errors: int = 0
    skipped_sources: list[str] = field(default_factory=list)       # no API key
    disabled_sources: dict[str, str] = field(default_factory=dict)  # stopped mid-scan -> reason


ProgressFn = Callable[[IPResult], None]
EventFn = Callable[[str, str], None]          # (level, message)
IPInfoFn = Callable[[str], Awaitable[dict]]


class AllSourcesDisabled(RuntimeError):
    pass


class Scanner:
    def __init__(
        self,
        options: ScanOptions | None = None,
        on_result: ProgressFn | None = None,
        registry: dict[str, type[Source]] | None = None,
        keys: dict[str, list[str]] | None = None,
        store: Store | None = None,
        ip_info: IPInfoFn | None = None,
        on_event: EventFn | None = None,
        resolver: AsyncResolver | None = None,
    ):
        self.options = options or ScanOptions()
        self.on_result = on_result
        self.on_event = on_event
        self.registry = registry or REGISTRY
        self.keys = keys or {}
        self.store = store
        self.ip_info = ip_info
        self.resolver = resolver
        self.stats = ScanStats()
        self._session: aiohttp.ClientSession | None = None
        self._strikes: dict[str, int] = {}
        unknown = [s for s in self.options.sources if s not in self.registry]
        if unknown:
            raise ValueError(f"unknown source(s): {', '.join(unknown)}")

    def _event(self, level: str, msg: str) -> None:
        if self.on_event:
            self.on_event(level, msg)

    # ------------------------------------------------------------ run

    async def run(self, ips: list[str], collect: bool = True) -> list[IPResult]:
        """Scan all IPs. With collect=False nothing is kept in memory and [] is returned."""
        o = self.options
        if o.ip_info and self.ip_info is None:
            self.ip_info = ASNResolver(timeout=min(o.timeout, 5)).lookup
        if o.validate and self.resolver is None:
            self.resolver = AsyncResolver(timeout=min(o.timeout, 5), concurrency=o.dns_concurrency)

        connector = aiohttp.TCPConnector(limit=100)
        headers = {"User-Agent": f"IPScope/{__version__}"}
        async with aiohttp.ClientSession(connector=connector, headers=headers, trust_env=True) as session:
            self._session = session
            ctx = SourceContext(session, o.timeout, o.retries, list(o.tls_ports), self.keys)
            built = [self.registry[name](ctx) for name in o.sources]
            self.sources = [s for s in built if s.available]
            self.stats.skipped_sources = [s.name for s in built if not s.available]
            if not self.sources:
                raise ValueError("no usable sources (keyed sources need an API key: ipscope keys set NAME)")
            self._probe_sem = asyncio.Semaphore(max(1, o.probe_concurrency))

            results: dict[int, IPResult] = {}
            work = iter(enumerate(ips))

            async def worker():
                for idx, ip in work:   # the shared iterator hands each IP to exactly one worker
                    r = await self._scan_ip(ip)
                    if collect:
                        results[idx] = r

            tasks = [asyncio.create_task(worker()) for _ in range(max(1, min(o.concurrency, len(ips))))]
            try:
                await asyncio.gather(*tasks)
            except BaseException:
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
        return [results[i] for i in sorted(results)] if collect else []

    # ------------------------------------------------------------ per IP

    def _live_sources(self) -> list[Source]:
        live = [s for s in self.sources if s.name not in self.stats.disabled_sources]
        if not live:
            reasons = "; ".join(f"{k}: {v}" for k, v in self.stats.disabled_sources.items())
            raise AllSourcesDisabled(f"all sources were switched off ({reasons})")
        return live

    def _disable(self, src: Source, reason: str) -> None:
        if src.name not in self.stats.disabled_sources:
            self.stats.disabled_sources[src.name] = reason
            self._event("warn", f"source '{src.name}' switched off for the rest of the scan: {reason}")

    async def _lookup(self, src: Source, ip: str) -> list[DomainRecord]:
        o = self.options
        if self.store and o.use_cache:
            hit = self.store.cache_get(src.name, ip, o.cache_ttl)
            if hit is not None:
                self.stats.cache_hits += 1
                return hit
        self.stats.requests += 1
        recs = await src.lookup(ip)
        if self.store:
            self.store.cache_put(src.name, ip, recs)  # only successful lookups are cached
        return recs

    async def _get_ip_info(self, ip: str) -> dict:
        try:
            return await self.ip_info(ip) if self.ip_info else {}
        except Exception:
            return {}

    def _record(self, src: Source, out, result: IPResult) -> None:
        if isinstance(out, Exception):
            self.stats.errors += 1
            result.errors[src.name] = str(out) or type(out).__name__
            if isinstance(out, (QuotaExceeded, KeyRejected)):
                self._disable(src, str(out))
            elif isinstance(out, RateLimited):
                self._strikes[src.name] = self._strikes.get(src.name, 0) + 1
                if self._strikes[src.name] >= RATE_LIMIT_STRIKES:
                    self._disable(src, f"rate limited on {RATE_LIMIT_STRIKES} IPs in a row")
        elif isinstance(out, BaseException):
            raise out
        else:
            self._strikes[src.name] = 0
            for rec in out:
                result.add(rec)

    async def _scan_ip(self, ip: str) -> IPResult:
        result = IPResult(ip)
        sources = self._live_sources()
        info_task = asyncio.create_task(self._get_ip_info(ip)) if self.options.ip_info else None
        local = next((x for x in sources if x.name == "local"), None)
        if self.options.local_first and local is not None and local.name not in self.stats.disabled_sources:
            try:
                out = await self._lookup(local, ip)
            except Exception as e:  # noqa: BLE001 - recorded per source
                out = e
            self._record(local, out, result)
            sources = [] if result.domains else [x for x in sources if x is not local]
        if self.options.first_hit:
            rank = {n: i for i, n in enumerate(CASCADE_ORDER)}
            for src in sorted(sources, key=lambda s: rank.get(s.name, len(rank))):
                if src.name in self.stats.disabled_sources:
                    continue
                try:
                    out = await self._lookup(src, ip)
                except Exception as e:  # noqa: BLE001 - recorded per source
                    out = e
                self._record(src, out, result)
                if result.domains:
                    break   # found it: don't ask the remaining sources
        else:
            outcomes = await asyncio.gather(*(self._lookup(s, ip) for s in sources), return_exceptions=True)
            for src, out in zip(sources, outcomes):
                self._record(src, out, result)
        if info_task:
            result.info = await info_task

        if self.options.validate and result.domains:
            await self._validate(result)
        for d in result.domains.values():
            d.root = root_domain(d.domain)
            d.confidence = confidence(d)
        probe_hosts = collapse_to_roots(result) if self.options.roots_only else {}
        if self.options.ip_info:
            result.info["hosting"] = hosting_type(result.info.get("category"), len(result.domains))
        if self.options.probe and result.domains:
            await self._probe(result, probe_hosts)
        if self.on_result:
            self.on_result(result)
        return result

    async def _validate(self, result: IPResult) -> None:
        async def check(d):
            res = await self.resolver.resolve(d.domain)
            d.resolved_ips = res or []
            d.status = classify(result.ip, res)

        await asyncio.gather(*(check(d) for d in result.domains.values()))

    async def _probe(self, result: IPResult, hosts: dict[str, str] | None = None) -> None:
        domains = result.sorted_domains()
        if self.options.validate:  # only sites that are actually on this IP now
            domains = [d for d in domains if d.status == Status.ACTIVE]
        domains = sorted(domains, key=lambda d: -d.confidence)[: self.options.probe_limit]

        async def one(d):
            async with self._probe_sem:
                host = (hosts or {}).get(d.domain, d.domain)
                d.http = await probe(self._session, host, timeout=min(self.options.timeout, 10))

        await asyncio.gather(*(one(d) for d in domains))
