from __future__ import annotations

import asyncio
import socket

from ipscope.models import DomainRecord, normalize_domain
from ipscope.sources.base import Source


class PTR(Source):
    name = "ptr"
    description = "Reverse DNS (PTR record) via your system resolver"
    rate = 0

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        try:
            host, aliases, _ = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyaddr, ip), self.ctx.timeout
            )
        except (socket.herror, socket.gaierror, TimeoutError, OSError):
            return []
        out = []
        for name in [host, *aliases]:
            d = normalize_domain(name)
            if d:
                out.append(DomainRecord(d, self.name))
        return out
