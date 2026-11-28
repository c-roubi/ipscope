"""HTTP probing: status, final URL, <title>, server header and technology fingerprints."""

from __future__ import annotations

import asyncio
import html
import re
from collections.abc import Iterable, Mapping

import aiohttp

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
MAX_BYTES = 256 * 1024

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(rb"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,60})["']""", re.I)
_CHARSET = re.compile(rb"""<meta[^>]+charset=["']?([A-Za-z0-9_-]+)""", re.I)

# (technology, where, regex). where: "header:<name>" | "cookie" | "html"
SIGNATURES: list[tuple[str, str, str]] = [
    # web servers
    ("nginx", "header:server", r"nginx"),
    ("Apache", "header:server", r"apache"),
    ("Microsoft IIS", "header:server", r"microsoft-iis"),
    ("LiteSpeed", "header:server", r"litespeed"),
    ("OpenResty", "header:server", r"openresty"),
    ("Caddy", "header:server", r"caddy"),
    # CDN / edge / hosting platforms
    ("Cloudflare", "header:cf-ray", r"."),
    ("Amazon CloudFront", "header:x-amz-cf-id", r"."),
    ("Fastly", "header:x-served-by", r"cache-"),
    ("Varnish", "header:via", r"varnish"),
    ("Akamai", "header:x-akamai-transformed", r"."),
    ("Sucuri", "header:x-sucuri-id", r"."),
    ("Imperva", "header:x-iinfo", r"."),
    ("Vercel", "header:x-vercel-id", r"."),
    ("Netlify", "header:x-nf-request-id", r"."),
    ("GitHub Pages", "header:x-github-request-id", r"."),
    # languages / frameworks
    ("PHP", "header:x-powered-by", r"php"),
    ("ASP.NET", "header:x-powered-by", r"asp\.net"),
    ("ASP.NET", "header:x-aspnet-version", r"."),
    ("Express", "header:x-powered-by", r"express"),
    ("Next.js", "header:x-powered-by", r"next\.js"),
    ("PHP", "cookie", r"^phpsessid="),
    ("ASP.NET", "cookie", r"^asp\.net_sessionid="),
    ("Java", "cookie", r"^jsessionid="),
    ("Laravel", "cookie", r"^laravel_session="),
    ("Django", "cookie", r"^csrftoken=.*"),
    ("Next.js", "html", r"__NEXT_DATA__"),
    ("Nuxt.js", "html", r"__NUXT__|/_nuxt/"),
    ("Angular", "html", r"ng-version="),
    ("React", "html", r"data-reactroot|react-dom"),
    ("Vue.js", "html", r"data-v-[0-9a-f]{8}|vue(\.min)?\.js"),
    ("jQuery", "html", r"jquery[.-]?[\d.]*(\.min)?\.js"),
    ("Bootstrap", "html", r"bootstrap(\.min)?\.(css|js)"),
    # CMS / site builders / shops
    ("WordPress", "html", r"/wp-content/|/wp-includes/"),
    ("WordPress", "cookie", r"^wordpress_|^wp-settings"),
    ("WooCommerce", "html", r"woocommerce"),
    ("Joomla", "html", r"/media/jui/|joomla!"),
    ("Drupal", "html", r"drupal\.settings|/sites/default/files"),
    ("Drupal", "header:x-drupal-cache", r"."),
    ("Magento", "html", r"mage/cookies|/static/version\d+/frontend/"),
    ("Shopify", "html", r"cdn\.shopify\.com"),
    ("Shopify", "header:x-shopid", r"."),
    ("Wix", "html", r"static\.wixstatic\.com"),
    ("Wix", "header:x-wix-request-id", r"."),
    ("Squarespace", "html", r"static\d*\.squarespace\.com"),
    ("Ghost", "html", r"ghost-(?:url|portal)"),
    # analytics
    ("Google Analytics", "html", r"googletagmanager\.com/gtag|google-analytics\.com/(analytics|ga)\.js"),
    ("Google Tag Manager", "html", r"googletagmanager\.com/gtm\.js"),
]

_COMPILED = [(name, where, re.compile(pat, re.I)) for name, where, pat in SIGNATURES]


def extract_title(body: bytes, charset: str | None = None) -> str | None:
    m = _TITLE.search(body)
    if not m:
        return None
    if not charset:
        cm = _CHARSET.search(body[:4096])
        charset = cm.group(1).decode() if cm else "utf-8"
    try:
        text = m.group(1).decode(charset, "replace")
    except LookupError:
        text = m.group(1).decode("utf-8", "replace")
    text = " ".join(html.unescape(text).split())
    return text[:200] or None


def detect_tech(headers: Mapping[str, str], cookies: Iterable[str], body: bytes) -> list[str]:
    hdr = {k.lower(): v for k, v in headers.items()}
    cookie_list = [c.strip() for c in cookies]
    text = body.decode("utf-8", "ignore")
    found: list[str] = []
    for name, where, rx in _COMPILED:
        if name in found:
            continue
        if where.startswith("header:"):
            v = hdr.get(where[7:])
            hit = v is not None and rx.search(v)
        elif where == "cookie":
            hit = any(rx.search(c) for c in cookie_list)
        else:
            hit = rx.search(text)
        if hit:
            found.append(name)
    gen = _GENERATOR.search(body)
    if gen:
        g = gen.group(1).decode("utf-8", "ignore").strip()
        if g and not any(g.lower().startswith(f.lower()) for f in found):
            found.append(g)
    return found


async def probe(
    session: aiohttp.ClientSession,
    host: str,
    timeout: float = 10.0,
    schemes: tuple[str, ...] = ("https", "http"),
) -> dict:
    """Fetch the site's front page. Never raises; returns {'error': ...} on failure."""
    last = "no response"
    for scheme in schemes:
        url = f"{scheme}://{host}/"
        try:
            async with session.get(
                url, ssl=False, allow_redirects=True, max_redirects=5,
                headers={"User-Agent": UA, "Accept": "text/html,*/*"},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                body = await resp.content.read(MAX_BYTES)
                cookies = []
                for r in (*resp.history, resp):
                    cookies += r.headers.getall("Set-Cookie", [])
                ctype = resp.headers.get("Content-Type", "")
                is_html = "html" in ctype.lower() or body.lstrip()[:1] == b"<"
                return {
                    "url": str(resp.url),
                    "status": resp.status,
                    "title": extract_title(body, resp.charset) if is_html else None,
                    "server": resp.headers.get("Server"),
                    "tech": detect_tech(resp.headers, cookies, body if is_html else b""),
                }
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError) as e:
            last = str(e) or type(e).__name__
    return {"error": last[:200]}
