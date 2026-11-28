from __future__ import annotations

from typing import Any

from ipscope.models import DomainRecord, normalize_domain
from ipscope.sources.base import Source


class AlienVaultOTX(Source):
    name = "otx"
    description = "AlienVault OTX passive DNS (free; optional key raises limits)"
    rate = 1.0
    key_env = "IPSCOPE_OTX_KEY"
    URL = "https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/passive_dns"

    def _auth(self, key):
        return {}, {"X-OTX-API-KEY": key}

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        kind = "IPv6" if ":" in ip else "IPv4"
        data = await self._fetch(self.URL.format(kind=kind, ip=ip), as_json=True)
        return self.parse(data, self.name)

    @staticmethod
    def parse(data: Any, source: str = "otx") -> list[DomainRecord]:
        out = []
        if not isinstance(data, dict):
            return out
        for entry in data.get("passive_dns") or []:
            if entry.get("record_type") not in (None, "A", "AAAA"):
                continue
            d = normalize_domain(entry.get("hostname"))
            if d:
                out.append(DomainRecord(d, source, entry.get("first"), entry.get("last")))
        return out
