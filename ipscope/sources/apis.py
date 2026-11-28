"""Reverse-IP sources that use official JSON APIs."""

from __future__ import annotations

from typing import Any

from ipscope.models import DomainRecord, normalize_domain
from ipscope.sources.base import KeyRejected, QuotaExceeded, Source, SourceError


def _records(names, source: str) -> list[DomainRecord]:
    seen: dict[str, DomainRecord] = {}
    for n in names or []:
        d = normalize_domain(n) if isinstance(n, str) else None
        if d and d not in seen:
            seen[d] = DomainRecord(d, source)
    return list(seen.values())


def _raise_for_message(msg: str) -> None:
    low = msg.lower()
    if any(w in low for w in ("limit", "quota", "exceeded", "too many")):
        raise QuotaExceeded(msg[:200])
    if "key" in low and any(w in low for w in ("invalid", "expired", "revoked", "unauthor")):
        raise KeyRejected(msg[:200])
    raise SourceError(msg[:200])


class DNSRift(Source):
    """https://dnsrift.net/docs - free plan needs no key."""
    name = "dnsrift"
    description = "DNSRift passive DNS (free, no key; optional key for paid plans)"
    rate = 1.0
    key_env = "IPSCOPE_DNSRIFT_KEY"
    URL = "https://api.dnsrift.net/reverse-ip-lookup"

    def _auth(self, key):
        return {"key": key}, {}

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        return self.parse(await self._fetch(self.URL, params={"ip": ip}, as_json=True), self.name)

    @staticmethod
    def parse(data: Any, source: str = "dnsrift") -> list[DomainRecord]:
        if data is None:
            return []
        if not isinstance(data, dict):
            raise SourceError("unexpected response")
        if data.get("message") and not data.get("domain_list"):
            msg = str(data["message"])
            if "no domain" in msg.lower() or "not found" in msg.lower():
                return []
            _raise_for_message(msg)
        return _records(data.get("domain_list"), source)


class THC(Source):
    """https://ip.thc.org - free, no key. 250-request burst, refilled at 0.5/s per IP."""
    name = "thc"
    description = "ip.thc.org reverse DNS (free, no key, very large dataset)"
    rate = 0.5
    max_pages = 5           # 200 per page -> up to 1,000 domains per IP
    URL = "https://ip.thc.org/api/v1/lookup"

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        out: list[DomainRecord] = []
        state = None
        for _ in range(self.max_pages):
            body = {"ip_address": ip, "limit": 200}
            if state:
                body["page_state"] = state
            data = await self._fetch(self.URL, method="POST", json_body=body, as_json=True)
            recs, state = self.parse(data, self.name)
            out += recs
            if not state:
                break
        return out

    @staticmethod
    def parse(data: Any, source: str = "thc") -> tuple[list[DomainRecord], str | None]:
        if not isinstance(data, dict):
            return [], None
        names = [d.get("domain") for d in data.get("domains") or [] if isinstance(d, dict)]
        return _records(names, source), data.get("next_page_state") or None


class RapidDNS(Source):
    """https://rapiddns.io/help/api - API key from a Pro / Pro Plus / Max account."""
    name = "rapiddns"
    description = "RapidDNS same-IP search via the official API (Pro key required)"
    rate = 1.0              # shared limit is 60 requests/minute per IP
    key_env = "IPSCOPE_RAPIDDNS_KEY"
    requires_key = True
    max_pages = 5
    PAGE = 500
    URL = "https://rapiddns.io/api/search/{q}"

    def _auth(self, key):
        return {}, {"X-API-KEY": key}

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        out: list[DomainRecord] = []
        for page in range(1, self.max_pages + 1):
            data = await self._fetch(self.URL.format(q=ip), as_json=True,
                                     params={"search_type": "ip", "page": str(page), "pagesize": str(self.PAGE)})
            recs, total = self.parse(data, self.name)
            out += recs
            if not recs or page * self.PAGE >= total:
                break
        return out

    @staticmethod
    def parse(data: Any, source: str = "rapiddns") -> tuple[list[DomainRecord], int]:
        if data is None:
            return [], 0
        if not isinstance(data, dict):
            raise SourceError("unexpected response")
        msg = data.get("message")
        if not isinstance(msg, dict):
            _raise_for_message(str(msg or data.get("error") or "unexpected response"))
        if msg.get("status") not in (None, "ok"):
            _raise_for_message(str(msg.get("error") or msg.get("status")))
        rows = msg.get("data") or []
        names = [r.get("subdomain") for r in rows if isinstance(r, dict)]
        return _records(names, source), int(msg.get("total") or 0)


class NetworksDB(Source):
    """https://networksdb.io/api/docs - free key: 1,000 requests/month, first page only."""
    name = "networksdb"
    description = "NetworksDB domains-on-IP via the official API (free key: 1,000/month)"
    rate = 1.0
    key_env = "IPSCOPE_NETWORKSDB_KEY"
    requires_key = True
    max_pages = 5
    URL = "https://networksdb.io/api/reverse-dns"

    def _auth(self, key):
        return {}, {"X-Api-Key": key}

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        data = await self._fetch(self.URL, params={"ip": ip}, as_json=True)
        recs, total = self.parse(data, self.name)
        page = 1
        while len(recs) < total and page < self.max_pages:   # paid plans only
            page += 1
            try:
                more, _ = self.parse(await self._fetch(self.URL, params={"ip": ip, "page": str(page)}, as_json=True),
                                     self.name)
            except SourceError:
                break
            if not more:
                break
            recs += more
        return recs

    @staticmethod
    def parse(data: Any, source: str = "networksdb") -> tuple[list[DomainRecord], int]:
        if data is None:
            return [], 0
        if not isinstance(data, dict):
            raise SourceError("unexpected response")
        if data.get("error") or data.get("message"):
            _raise_for_message(str(data.get("error") or data.get("message")))
        res = data.get("results") or []
        return _records(res, source), int(data.get("total") or len(res))


class WebScan(Source):
    """api.webscan.cc - free JSON endpoint without public docs (may change without notice)."""
    name = "webscan"
    description = "webscan.cc same-IP API (free, undocumented - may stop working)"
    rate = 1.0
    URL = "https://api.webscan.cc/"

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        return self.parse(await self._fetch(self.URL, params={"action": "query", "ip": ip}, as_json=True), self.name)

    @staticmethod
    def parse(data: Any, source: str = "webscan") -> list[DomainRecord]:
        if not data:
            return []
        if isinstance(data, dict):
            data = data.get("data") or data.get("list") or []
        if not isinstance(data, list):
            return []
        return _records([d.get("domain") for d in data if isinstance(d, dict)], source)
