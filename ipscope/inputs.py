"""Turn user input (IPs, CIDRs, ASNs, domains, URLs) into a list of IPs to scan."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from urllib.parse import urlparse

import aiohttp

from ipscope.dns import resolve
from ipscope.enrich.asn import asn_prefixes
from ipscope.models import normalize_domain

_ASN = re.compile(r"^as(\d{1,10})$", re.I)

PrefixFn = Callable[[int], Awaitable[list[str]]]


async def expand_targets(
    items: list[str],
    *,
    allow_private: bool = False,
    max_hosts: int = 65536,
    timeout: float = 5.0,
    asn_lookup: PrefixFn | None = None,
) -> tuple[list[str], list[str]]:
    """Return (unique IPs in input order, warnings). max_hosts caps the total."""
    ips: list[str] = []
    seen: set[str] = set()
    warnings: list[str] = []
    skipped_private = 0

    def add(ip) -> None:
        nonlocal skipped_private
        if not allow_private and not ip.is_global:
            skipped_private += 1
            return
        s = str(ip)
        if s not in seen:
            seen.add(s)
            ips.append(s)

    def add_network(net, label: str) -> bool:
        """Add every host of a network; False if it would exceed the total limit."""
        if len(ips) + net.num_addresses > max_hosts:
            warnings.append(f"{label}: {net.num_addresses} addresses would exceed --max-hosts "
                            f"{max_hosts}, skipped")
            return False
        for h in (list(net) if net.num_addresses <= 2 else net.hosts()):
            add(h)
        return True

    async with AsyncExitStack() as stack:
        for raw in items:
            t = raw.strip()
            if not t or t.startswith("#"):
                continue
            if "://" in t:
                t = urlparse(t).hostname or ""

            m = _ASN.match(t)
            if m:
                asn = int(m.group(1))
                if asn_lookup is None:
                    session = await stack.enter_async_context(aiohttp.ClientSession(trust_env=True))
                    asn_lookup = lambda n, s=session: asn_prefixes(s, n)  # noqa: E731
                try:
                    prefixes = await asn_lookup(asn)
                except Exception as e:
                    warnings.append(f"AS{asn}: could not fetch prefixes ({e})")
                    continue
                v4 = [ipaddress.ip_network(p, strict=False) for p in prefixes if ":" not in p]
                v6 = len(prefixes) - len(v4)
                if not v4:
                    warnings.append(f"AS{asn}: no IPv4 prefixes announced")
                total = sum(n.num_addresses for n in v4)
                if total + len(ips) > max_hosts:
                    warnings.append(f"AS{asn}: {total} IPv4 addresses in {len(v4)} prefixes; "
                                    f"only prefixes that fit --max-hosts {max_hosts} are scanned")
                for net in sorted(v4, key=lambda n: n.num_addresses):
                    if len(ips) + net.num_addresses > max_hosts:
                        break
                    add_network(net, f"AS{asn} {net}")
                if v6:
                    warnings.append(f"AS{asn}: skipped {v6} IPv6 prefix(es) (too large to enumerate)")
                continue

            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                net = None
            if net is not None:
                add_network(net, t)
                continue

            d = normalize_domain(t)
            if not d:
                warnings.append(f"{raw.strip()}: not a valid IP, CIDR, ASN or domain")
                continue
            resolved = await resolve(d, timeout)
            if not resolved:
                warnings.append(f"{d}: could not be resolved")
                continue
            for addr in resolved:
                add(ipaddress.ip_address(addr.split("%")[0]))

    if skipped_private:
        warnings.append(f"skipped {skipped_private} private/reserved address(es) (use --allow-private)")
    return ips, warnings
