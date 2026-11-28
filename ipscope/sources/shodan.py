from __future__ import annotations

from typing import Any

from ipscope.models import DomainRecord, normalize_domain
from ipscope.sources.base import Source


def _records(names, source: str) -> list[DomainRecord]:
    seen: dict[str, DomainRecord] = {}
    for n in names:
        d = normalize_domain(n) if isinstance(n, str) else None
        if d and d not in seen:
            seen[d] = DomainRecord(d, source)
    return list(seen.values())


class Shodan(Source):
    name = "shodan"
    description = "Shodan host data: hostnames, HTTP Host headers, TLS cert CNs (key required)"
    rate = 1.0
    key_env = "IPSCOPE_SHODAN_KEY"
    requires_key = True
    URL = "https://api.shodan.io/shodan/host/{ip}"

    def _auth(self, key):
        return {"key": key}, {}

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        data = await self._fetch(self.URL.format(ip=ip), as_json=True)
        return self.parse(data, self.name)

    @staticmethod
    def parse(data: Any, source: str = "shodan") -> list[DomainRecord]:
        if not isinstance(data, dict):
            return []
        names = list(data.get("hostnames") or [])
        # note: Shodan's "domains" field holds root domains derived from PTR
        # records (e.g. amazonaws.com), which are misleading here, so it is skipped
        for svc in data.get("data") or []:
            if not isinstance(svc, dict):
                continue
            names += svc.get("hostnames") or []
            http = svc.get("http") or {}
            if isinstance(http, dict):
                names.append(http.get("host"))
            cert = ((svc.get("ssl") or {}).get("cert") or {})
            subject = cert.get("subject") or {}
            if isinstance(subject, dict):
                names.append(subject.get("CN"))
        return _records(names, source)


class InternetDB(Source):
    name = "internetdb"
    description = "Shodan InternetDB (free, no key): hostnames seen on the IP"
    rate = 1.0
    URL = "https://internetdb.shodan.io/{ip}"

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        data = await self._fetch(self.URL.format(ip=ip), as_json=True)
        return self.parse(data, self.name)

    @staticmethod
    def parse(data: Any, source: str = "internetdb") -> list[DomainRecord]:
        if not isinstance(data, dict):
            return []
        return _records(data.get("hostnames") or [], source)
