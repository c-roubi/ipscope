from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ipscope.models import DomainRecord, normalize_domain
from ipscope.sources.base import Source


def _iso(ts: Any) -> str | None:
    if isinstance(ts, (int, float)) and ts > 0:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return None


class VirusTotal(Source):
    name = "virustotal"
    description = "VirusTotal passive DNS resolutions (free key: 4 req/min, 500/day)"
    rate = 4 / 60
    key_env = "IPSCOPE_VIRUSTOTAL_KEY"
    requires_key = True
    URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"

    def _auth(self, key):
        return {}, {"x-apikey": key}

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        out: list[DomainRecord] = []
        params = {"limit": "40"}
        for _ in range(self.max_pages):
            data = await self._fetch(self.URL.format(ip=ip), params=params, as_json=True)
            recs, cursor = self.parse(data, self.name)
            out.extend(recs)
            if not cursor:
                break
            params = {"limit": "40", "cursor": cursor}
        return out

    @staticmethod
    def parse(data: Any, source: str = "virustotal") -> tuple[list[DomainRecord], str | None]:
        if not isinstance(data, dict):
            return [], None
        out = []
        for item in data.get("data") or []:
            attrs = item.get("attributes") or {}
            d = normalize_domain(attrs.get("host_name"))
            if d:
                seen = _iso(attrs.get("date"))
                out.append(DomainRecord(d, source, seen, seen))
        cursor = (data.get("meta") or {}).get("cursor") or None
        return out, cursor
