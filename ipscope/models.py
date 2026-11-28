"""Core data models and domain normalization."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_domain(name: str | None) -> str | None:
    """Clean a hostname; return None if it is not a usable domain name."""
    if not name:
        return None
    d = name.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if not d or any(c.isspace() for c in d):
        return None
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if len(d) > 253:
        return None
    try:
        ipaddress.ip_address(d)
        return None  # an IP address, not a domain
    except ValueError:
        pass
    labels = d.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return None
    if not all(_LABEL.match(label) for label in labels):
        return None
    return d


# names that appear on default / placeholder certificates and pages, never real sites
PLACEHOLDER_NAMES = {
    "default.domain", "localhost.localdomain", "localdomain", "example.com", "www.example.com",
    "example.net", "example.org", "domain.com", "yourdomain.com", "your-domain.com", "server.domain.com",
    "traefik.default", "ingress.local", "kubernetes.default", "plesk.local", "invalid.invalid",
}
PLACEHOLDER_SUFFIXES = (
    ".local", ".localdomain", ".localhost", ".invalid", ".internal", ".lan", ".home.arpa",
    ".svc", ".cluster.local", ".traefik.default", ".example", ".test",
)


def is_placeholder(domain: str) -> bool:
    """True for default-certificate / test names that don't identify a real site."""
    return domain in PLACEHOLDER_NAMES or domain.endswith(PLACEHOLDER_SUFFIXES) \
        or domain.endswith(".ingress.local") or domain.startswith("traefik.")


class Status(str, Enum):
    UNKNOWN = "unknown"        # not validated
    ACTIVE = "active"          # currently resolves to the scanned IP
    HISTORICAL = "historical"  # resolves, but to other IPs now
    DEAD = "dead"              # does not resolve


@dataclass
class DomainRecord:
    """A single observation returned by one source."""
    domain: str
    source: str
    first_seen: str | None = None
    last_seen: str | None = None


@dataclass
class DomainResult:
    """A domain merged across all sources for one IP."""
    domain: str
    sources: set[str] = field(default_factory=set)
    first_seen: str | None = None
    last_seen: str | None = None
    status: Status = Status.UNKNOWN
    resolved_ips: list[str] = field(default_factory=list)
    root: str | None = None          # registrable domain, e.g. example.co.uk
    confidence: int = 0              # 0-100
    http: dict | None = None         # filled by --probe


@dataclass
class IPResult:
    ip: str
    domains: dict[str, DomainResult] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    info: dict = field(default_factory=dict)   # ASN / provider / hosting type

    def add(self, rec: DomainRecord) -> None:
        d = self.domains.get(rec.domain)
        if d is None:
            d = self.domains[rec.domain] = DomainResult(rec.domain)
        d.sources.add(rec.source)
        if rec.first_seen and (not d.first_seen or rec.first_seen < d.first_seen):
            d.first_seen = rec.first_seen
        if rec.last_seen and (not d.last_seen or rec.last_seen > d.last_seen):
            d.last_seen = rec.last_seen

    def sorted_domains(self) -> list[DomainResult]:
        return [self.domains[k] for k in sorted(self.domains)]

    def count(self, status: Status) -> int:
        return sum(1 for d in self.domains.values() if d.status == status)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "errors": self.errors,
            "info": self.info,
            "domains": [
                {
                    "domain": d.domain,
                    "sources": sorted(d.sources),
                    "first_seen": d.first_seen,
                    "last_seen": d.last_seen,
                    "status": d.status.value,
                    "resolved_ips": d.resolved_ips,
                    "root": d.root,
                    "confidence": d.confidence,
                    "http": d.http,
                }
                for d in self.sorted_domains()
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IPResult":
        r = cls(data["ip"], errors=dict(data.get("errors") or {}), info=dict(data.get("info") or {}))
        for d in data.get("domains") or []:
            r.domains[d["domain"]] = DomainResult(
                domain=d["domain"],
                sources=set(d.get("sources") or []),
                first_seen=d.get("first_seen"),
                last_seen=d.get("last_seen"),
                status=Status(d.get("status", "unknown")),
                resolved_ips=list(d.get("resolved_ips") or []),
                root=d.get("root"),
                confidence=int(d.get("confidence") or 0),
                http=d.get("http"),
            )
        return r
