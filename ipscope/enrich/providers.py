"""Identify CDNs, clouds and hosting companies from IP ranges and ASNs."""

from __future__ import annotations

import ipaddress

# Cloudflare publishes these ranges (cloudflare.com/ips); checked offline first.
_CLOUDFLARE = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
STATIC_RANGES = [(ipaddress.ip_network(n), "Cloudflare", "cdn") for n in _CLOUDFLARE]

# ASN -> (provider, category). category: cdn | cloud | hosting
ASN_PROVIDERS: dict[int, tuple[str, str]] = {
    # CDN / reverse proxy / WAF
    13335: ("Cloudflare", "cdn"), 209242: ("Cloudflare", "cdn"),
    20940: ("Akamai", "cdn"), 16625: ("Akamai", "cdn"), 21342: ("Akamai", "cdn"),
    32787: ("Akamai Prolexic", "cdn"), 54113: ("Fastly", "cdn"),
    19551: ("Imperva", "cdn"), 30148: ("Sucuri", "cdn"), 60068: ("CDN77", "cdn"),
    200325: ("Bunny CDN", "cdn"), 12989: ("StackPath", "cdn"), 33438: ("StackPath", "cdn"),
    15133: ("Edgio/Edgecast", "cdn"), 22822: ("Edgio/Limelight", "cdn"),
    # Cloud
    16509: ("Amazon AWS", "cloud"), 14618: ("Amazon AWS", "cloud"),
    15169: ("Google", "cloud"), 396982: ("Google Cloud", "cloud"),
    8075: ("Microsoft Azure", "cloud"), 14061: ("DigitalOcean", "cloud"),
    63949: ("Akamai Linode", "cloud"), 20473: ("Vultr", "cloud"),
    31898: ("Oracle Cloud", "cloud"), 45102: ("Alibaba Cloud", "cloud"),
    132203: ("Tencent Cloud", "cloud"),
    # Hosting
    16276: ("OVH", "hosting"), 24940: ("Hetzner", "hosting"),
    46606: ("Unified Layer (Bluehost/HostGator)", "hosting"),
    26496: ("GoDaddy", "hosting"), 398101: ("GoDaddy", "hosting"),
    47583: ("Hostinger", "hosting"), 22612: ("Namecheap", "hosting"),
    51167: ("Contabo", "hosting"), 12876: ("Scaleway", "hosting"),
    197695: ("Reg.ru", "hosting"), 36352: ("ColoCrossing", "hosting"),
    32244: ("Liquid Web", "hosting"), 19871: ("Network Solutions", "hosting"),
}


def detect_provider(ip: str, asn: int | None, as_name: str | None) -> tuple[str | None, str | None]:
    """Return (provider name, category) - category is None when unknown."""
    try:
        addr = ipaddress.ip_address(ip)
        for net, name, cat in STATIC_RANGES:
            if addr.version == net.version and addr in net:
                return name, cat
    except ValueError:
        pass
    if asn in ASN_PROVIDERS:
        return ASN_PROVIDERS[asn]
    if as_name:
        # Team Cymru names look like "HETZNER-AS, DE" - keep the readable part
        return as_name.rsplit(",", 1)[0].strip() or None, None
    return None, None


def hosting_type(category: str | None, n_domains: int) -> str:
    if category == "cdn":
        return "cdn-edge"
    if n_domains >= 50:
        return "shared"
    if n_domains >= 5:
        return "multi-site"
    if n_domains >= 1:
        return "single-site"
    return "unknown"
