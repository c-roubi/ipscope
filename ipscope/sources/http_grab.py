"""Ask the server itself over HTTP(S), with the bare IP as the host.

Servers often give away their main site when hit by IP:
  * a redirect:              Location: https://www.example.com/
  * a canonical link:        <link rel="canonical" href="https://example.com/">
  * Open Graph / base URL:   <meta property="og:url" ...>, <base href=...>
Only these self-references are used; ordinary outbound links (facebook.com,
cdnjs...) are ignored because they are not hosted on the IP.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from urllib.parse import urljoin, urlparse

import aiohttp

from ipscope.models import DomainRecord, is_placeholder, normalize_domain
from ipscope.sources.base import Source

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
MAX_BYTES = 128 * 1024
REDIRECTS = (301, 302, 303, 307, 308)

_TAG = re.compile(rb"<(link|meta|base)\b[^>]*>", re.I)
_ATTR = re.compile(rb"""([a-zA-Z:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def self_references(body: bytes, base_url: str) -> list[str]:
    """Hostnames the page declares as its own URL."""
    urls = []
    for m in _TAG.finditer(body[:MAX_BYTES]):
        tag = m.group(1).lower()
        attrs = {}
        for a in _ATTR.finditer(m.group(0)):
            attrs[a.group(1).lower()] = (a.group(2) or a.group(3) or a.group(4) or b"").decode("utf-8", "ignore")
        if tag == b"link" and "canonical" in attrs.get(b"rel", "").lower().split():
            urls.append(attrs.get(b"href", ""))
        elif tag == b"meta" and attrs.get(b"property", "").lower() in ("og:url",):
            urls.append(attrs.get(b"content", ""))
        elif tag == b"base":
            urls.append(attrs.get(b"href", ""))
    hosts = []
    for u in urls:
        if not u:
            continue
        h = urlparse(urljoin(base_url, u.strip())).hostname
        if h and not _is_ip(h):
            hosts.append(h)
    return hosts


class HTTPGrab(Source):
    name = "http"
    description = "Requests http(s)://IP directly: redirects, canonical and og:url links (ACTIVE: contacts the target)"
    rate = 0
    active = True
    PORTS = [(80, "http"), (443, "https"), (8080, "http"), (8443, "https")]

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        host = f"[{ip}]" if ":" in ip else ip
        found = await asyncio.gather(*(self._grab(scheme, host, port) for port, scheme in self.PORTS))
        out: dict[str, DomainRecord] = {}
        for names in found:
            for n in names:
                d = normalize_domain(n)
                if d and d not in out and not is_placeholder(d):
                    out[d] = DomainRecord(d, self.name)
        return list(out.values())

    async def _grab(self, scheme: str, host: str, port: int) -> list[str]:
        if self.ctx.session is None:
            return []
        default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        url = f"{scheme}://{host}{'' if default else f':{port}'}/"
        names: list[str] = []
        timeout = aiohttp.ClientTimeout(total=min(self.ctx.timeout, 8), sock_connect=min(self.ctx.timeout, 4))
        try:
            for _ in range(4):
                async with self.ctx.session.get(
                    url, ssl=False, allow_redirects=False, timeout=timeout,
                    headers={"User-Agent": UA, "Accept": "text/html,*/*"},
                ) as resp:
                    loc = resp.headers.get("Location")
                    if resp.status in REDIRECTS and loc:
                        nxt = urljoin(url, loc)
                        h = urlparse(nxt).hostname
                        if h and not _is_ip(h):
                            names.append(h)  # found the site's name; don't follow it elsewhere
                            break
                        url = nxt          # e.g. http://IP -> https://IP: keep following on the IP
                        continue
                    ctype = resp.headers.get("Content-Type", "").lower()
                    if "html" in ctype or not ctype:
                        names += self_references(await resp.content.read(MAX_BYTES), str(resp.url))
                    break
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, UnicodeError, OSError):
            pass
        return names
