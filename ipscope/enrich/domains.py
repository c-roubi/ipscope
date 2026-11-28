"""Root-domain extraction (Public Suffix List) and confidence scoring."""

from __future__ import annotations

from functools import lru_cache

from ipscope.models import DomainResult, Status

try:
    import tldextract

    # bundled PSL snapshot only: no network access, no cache files
    _extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except ImportError:  # pragma: no cover
    _extract = None


@lru_cache(maxsize=65536)
def root_domain(domain: str) -> str:
    """'a.b.example.co.uk' -> 'example.co.uk'. Falls back to the last two labels."""
    if _extract is not None:
        r = _extract(domain)
        if r.domain and r.suffix:
            return f"{r.domain}.{r.suffix}"
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


_STATUS_BONUS = {Status.ACTIVE: 15, Status.UNKNOWN: 0, Status.HISTORICAL: -15, Status.DEAD: -30}


def confidence(d: DomainResult) -> int:
    """How sure we are the domain is (or was) on this IP: more sources + live DNS = higher."""
    n = len(d.sources)
    base = 0 if n == 0 else 40 if n == 1 else 65 if n == 2 else 85
    return max(0, min(100, base + _STATUS_BONUS[d.status]))
