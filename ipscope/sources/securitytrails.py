from __future__ import annotations

from typing import Any

from ipscope.models import DomainRecord, normalize_domain
from ipscope.sources.base import Source


class SecurityTrails(Source):
    name = "securitytrails"
    description = "SecurityTrails domain search by IPv4 (key required; free plan is very limited)"
    rate = 1.0
    key_env = "IPSCOPE_SECURITYTRAILS_KEY"
    requires_key = True
    URL = "https://api.securitytrails.com/v1/domains/list"

    def _auth(self, key):
        return {}, {"APIKEY": key}

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        if ":" in ip:
            return []  # this endpoint filters by IPv4
        out: list[DomainRecord] = []
        page = 1
        while page <= self.max_pages:
            data = await self._fetch(
                self.URL, method="POST",
                params={"include_ips": "false", "page": str(page), "scroll": "false"},
                headers={"Accept": "application/json"},
                json_body={"filter": {"ipv4": ip}},
                as_json=True,
            )
            recs, total_pages = self.parse(data, self.name)
            out.extend(recs)
            if page >= total_pages:
                break
            page += 1
        return out

    @staticmethod
    def parse(data: Any, source: str = "securitytrails") -> tuple[list[DomainRecord], int]:
        if not isinstance(data, dict):
            return [], 0
        out = []
        for rec in data.get("records") or []:
            d = normalize_domain(rec.get("hostname"))
            if d:
                out.append(DomainRecord(d, source))
        total = (data.get("meta") or {}).get("total_pages") or 1
        try:
            total = int(total)
        except (TypeError, ValueError):
            total = 1
        return out, total
