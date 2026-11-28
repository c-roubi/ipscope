from __future__ import annotations

from ipscope.models import DomainRecord, normalize_domain
from ipscope.sources.base import QuotaExceeded, Source, SourceError


class HackerTarget(Source):
    name = "hackertarget"
    description = "HackerTarget reverse IP API (free tier has a small daily quota)"
    rate = 0.5
    key_env = "IPSCOPE_HACKERTARGET_KEY"
    URL = "https://api.hackertarget.com/reverseiplookup/"

    def _auth(self, key):
        return {"apikey": key}, {}

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        while True:
            key = self.api_key
            text = await self._fetch(self.URL, params={"q": ip})
            try:
                return self.parse(text or "", self.name)
            except QuotaExceeded:
                # quota is reported in the body with HTTP 200, so rotate here
                if not self.rotate_key(key):
                    raise

    @staticmethod
    def parse(text: str, source: str = "hackertarget") -> list[DomainRecord]:
        low = text.strip().lower()
        if "api count exceeded" in low or "increase quota" in low:
            raise QuotaExceeded("daily quota exceeded")
        if low.startswith("error"):
            raise SourceError(text.strip()[:200])
        if low.startswith("no dns a records") or low.startswith("no records"):
            return []
        out = []
        for line in text.splitlines():
            d = normalize_domain(line)
            if d:
                out.append(DomainRecord(d, source))
        return out
