"""Source plugin registry. Add a new source by subclassing Source and listing it here."""

from ipscope.sources.apis import DNSRift, NetworksDB, RapidDNS, THC, WebScan
from ipscope.sources.base import KeyRejected, QuotaExceeded, RateLimited, Source, SourceContext, SourceError
from ipscope.sources.hackertarget import HackerTarget
from ipscope.sources.http_grab import HTTPGrab
from ipscope.sources.local import LocalIndexSource
from ipscope.sources.otx import AlienVaultOTX
from ipscope.sources.ptr import PTR
from ipscope.sources.securitytrails import SecurityTrails
from ipscope.sources.shodan import InternetDB, Shodan
from ipscope.sources.tls_cert import DEFAULT_TLS_PORTS, TLSCert
from ipscope.sources.virustotal import VirusTotal

REGISTRY: dict[str, type[Source]] = {
    cls.name: cls
    for cls in (
        LocalIndexSource,
        DNSRift, THC, HackerTarget, AlienVaultOTX, InternetDB, PTR, WebScan,
        VirusTotal, SecurityTrails, Shodan, RapidDNS, NetworksDB,
        TLSCert, HTTPGrab,
    )
}

# Free passive sources. Keyed sources join automatically once a key is set and
# "local" once an index has been built. "tls" and "http" contact the target,
# so they're opt-in (--active).
DEFAULT_SOURCES = ["dnsrift", "thc", "hackertarget", "otx", "internetdb", "ptr"]
ACTIVE_SOURCES = ["tls", "http"]

# Quick source sets (like "fast" vs "more domains" modes)
PRESETS = {
    "fast": {"sources": ["local", "dnsrift", "internetdb", "ptr"], "active": False,
             "help": "Quickest big sources only"},
    "free": {"sources": ["local", "dnsrift", "thc", "hackertarget", "otx", "internetdb", "ptr", "webscan"],
             "active": False, "help": "Every free passive source"},
    "full": {"sources": ["*"], "active": True,
             "help": "Everything you have set up, plus direct contact (tls, http)"},
    "offline": {"sources": ["local"], "active": False, "help": "Only your local index, no network"},
}


def _available(name: str, keys: dict[str, list[str]], has_index: bool) -> bool:
    cls = REGISTRY[name]
    if name == "local":
        return has_index
    return not cls.requires_key or bool(keys.get(name))


def default_sources(keys: dict[str, list[str]]) -> list[str]:
    from ipscope.index import LocalIndex

    names = list(DEFAULT_SOURCES)
    if LocalIndex.has_data():
        names.insert(0, "local")
    for name, cls in REGISTRY.items():
        if cls.requires_key and keys.get(name) and name not in names:
            names.append(name)
    return names


def preset_sources(preset: str, keys: dict[str, list[str]]) -> tuple[list[str], bool]:
    """Return (sources, active) for a preset, keeping only sources that are set up."""
    from ipscope.index import LocalIndex

    p = PRESETS[preset]
    has_index = LocalIndex.has_data()
    wanted = [n for n, c in REGISTRY.items() if not c.active] if p["sources"] == ["*"] else p["sources"]
    names = [n for n in wanted if _available(n, keys, has_index)]
    return names, p["active"]


__all__ = [
    "REGISTRY", "DEFAULT_SOURCES", "ACTIVE_SOURCES", "DEFAULT_TLS_PORTS", "PRESETS",
    "default_sources", "preset_sources",
    "Source", "SourceContext", "SourceError", "QuotaExceeded", "KeyRejected", "RateLimited",
]
