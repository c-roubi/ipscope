from __future__ import annotations

from datetime import datetime, timezone

from ipscope.index import LocalIndex, index_path
from ipscope.models import DomainRecord
from ipscope.sources.base import Source


def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class LocalIndexSource(Source):
    name = "local"
    description = "Your own offline index (ipscope index build) - instant, no limits"
    rate = 0

    def __init__(self, ctx):
        super().__init__(ctx)
        self._index: LocalIndex | None = None

    @property
    def available(self) -> bool:
        return LocalIndex.has_data()

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        if self._index is None:
            self._index = LocalIndex(index_path())
        return [DomainRecord(name, self.name, _iso(seen), _iso(seen)) for name, seen in self._index.lookup(ip)]
