import asyncio
import json

import aiohttp
from aiohttp import web
from typer.testing import CliRunner

from ipscope.engine import ScanOptions, Scanner
from ipscope.enrich.asn import cymru_origin_name, parse_asname, parse_origin, parse_ripestat
from ipscope.enrich.domains import confidence, root_domain
from ipscope.enrich.http_probe import detect_tech, extract_title, probe
from ipscope.enrich.providers import detect_provider, hosting_type
from ipscope.export import export
from ipscope.inputs import expand_targets
from ipscope.models import DomainRecord, DomainResult, IPResult, Status
from ipscope.sources import REGISTRY, Source


# ---------- providers / ASN ----------

def test_detect_provider():
    assert detect_provider("104.16.1.1", None, None) == ("Cloudflare", "cdn")          # static range
    assert detect_provider("2606:4700::1", None, None) == ("Cloudflare", "cdn")
    assert detect_provider("5.9.1.1", 24940, "HETZNER-AS, DE") == ("Hetzner", "hosting")
    assert detect_provider("1.2.3.4", 99999, "SOMEISP-AS, PS") == ("SOMEISP-AS", None)
    assert detect_provider("1.2.3.4", None, None) == (None, None)
    assert hosting_type("cdn", 3) == "cdn-edge"
    assert hosting_type(None, 120) == "shared"
    assert hosting_type("cloud", 7) == "multi-site"
    assert hosting_type(None, 1) == "single-site"


def test_cymru_parsing():
    assert cymru_origin_name("1.2.3.4") == "4.3.2.1.origin.asn.cymru.com"
    assert cymru_origin_name("2001:db8::1").endswith(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com")
    info = parse_origin([
        "13335 | 104.16.0.0/12 | US | arin | 2014-03-28",
        "13335 | 104.16.0.0/13 | US | arin | 2014-03-28",
        "garbage",
    ])
    assert info == {"asn": 13335, "prefix": "104.16.0.0/13", "country": "US", "registry": "arin"}
    assert parse_origin([]) == {}
    assert parse_asname(["13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"]) == "CLOUDFLARENET, US"
    assert parse_ripestat({"data": {"prefixes": [{"prefix": "1.0.0.0/24"}, {"prefix": "2606::/32"}]}}) \
        == ["1.0.0.0/24", "2606::/32"]


def test_expand_asn():
    async def fake_prefixes(asn):
        assert asn == 64500
        return ["8.8.8.0/30", "8.8.4.0/31", "2001:4860::/32"]

    ips, warns = asyncio.run(expand_targets(["AS64500", "as64500"], asn_lookup=fake_prefixes))
    assert ips == ["8.8.4.0", "8.8.4.1", "8.8.8.1", "8.8.8.2"]
    assert any("IPv6" in w for w in warns)

    ips, warns = asyncio.run(expand_targets(["AS64500"], asn_lookup=fake_prefixes, max_hosts=3))
    assert ips == ["8.8.4.0", "8.8.4.1"]   # /30 didn't fit in the remaining budget
    assert any("max-hosts" in w for w in warns)

    async def broken(asn):
        raise RuntimeError("down")

    ips, warns = asyncio.run(expand_targets(["AS1"], asn_lookup=broken))
    assert ips == [] and "could not fetch" in warns[0]


# ---------- domains ----------

def test_root_and_confidence():
    assert root_domain("a.b.example.co.uk") == "example.co.uk"
    assert root_domain("shop.example.com") == "example.com"
    assert root_domain("example.com") == "example.com"
    d = DomainResult("a.com", sources={"x"})
    assert confidence(d) == 40
    d.sources = {"x", "y", "z"}
    d.status = Status.ACTIVE
    assert confidence(d) == 100
    d.sources = {"x"}
    d.status = Status.DEAD
    assert confidence(d) == 10


# ---------- HTTP probe ----------

def test_title_and_tech():
    body = (b'<html><head><meta charset="utf-8"><title>\n  Caf&eacute; &amp; \xd9\x85\xd8\xb1\xd8\xad\xd8\xa8\xd8\xa7'
            b'  </title><meta name="generator" content="WordPress 6.4"></head>'
            b'<script src="/wp-includes/js/jquery/jquery.min.js"></script></html>')
    assert extract_title(body) == "Café & مرحبا"
    assert extract_title(b"<html>no title</html>") is None
    tech = detect_tech({"Server": "nginx/1.24", "X-Powered-By": "PHP/8.2", "CF-RAY": "abc"},
                       ["laravel_session=xyz; path=/"], body)
    assert {"nginx", "PHP", "Cloudflare", "Laravel", "WordPress", "jQuery"} <= set(tech)
    assert "WordPress 6.4" not in tech           # generator duplicate of a detected tech
    assert detect_tech({}, [], b'<meta name="generator" content="Hugo 0.120">') == ["Hugo 0.120"]


def test_probe_local_server():
    async def main():
        async def home(request):
            raise web.HTTPFound("/landing")

        async def landing(request):
            resp = web.Response(
                text="<html><head><title>Landing Page</title></head>"
                     "<body><div id=__NEXT_DATA__></div></body></html>",
                content_type="text/html",
            )
            resp.headers["Server"] = "Caddy"
            resp.set_cookie("PHPSESSID", "1")
            return resp

        app = web.Application()
        app.router.add_get("/", home)
        app.router.add_get("/landing", landing)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        async with aiohttp.ClientSession() as s:
            ok = await probe(s, f"127.0.0.1:{port}", timeout=5, schemes=("http",))
            bad = await probe(s, "127.0.0.1:1", timeout=2, schemes=("https", "http"))
        await runner.cleanup()
        return ok, bad

    ok, bad = asyncio.run(main())
    assert ok["status"] == 200 and ok["url"].endswith("/landing")
    assert ok["title"] == "Landing Page" and ok["server"] == "Caddy"
    assert {"Caddy", "Next.js", "PHP"} <= set(ok["tech"])
    assert "error" in bad


# ---------- engine + export ----------

class TwoSites(Source):
    name = "twosites"; rate = 0
    async def _lookup(self, ip):
        return [DomainRecord("www.example.co.uk", self.name), DomainRecord("shop.example.co.uk", self.name),
                DomainRecord("other.org", self.name)]


async def fake_info(ip):
    return {"asn": 13335, "as_name": "CLOUDFLARENET, US", "provider": "Cloudflare", "category": "cdn"}


def test_engine_enrichment_and_export(tmp_path):
    reg = {"twosites": TwoSites}
    scanner = Scanner(ScanOptions(sources=["twosites"]), registry=reg, ip_info=fake_info)
    [r] = asyncio.run(scanner.run(["104.16.1.1"]))
    assert r.info["provider"] == "Cloudflare" and r.info["hosting"] == "cdn-edge"
    assert r.domains["shop.example.co.uk"].root == "example.co.uk"
    assert r.domains["other.org"].confidence == 40

    back = IPResult.from_dict(json.loads(json.dumps(r.to_dict())))
    assert back.info == r.info and back.domains["other.org"].root == "other.org"

    assert export([r], tmp_path / "roots.txt", roots_only=True) == 2
    assert (tmp_path / "roots.txt").read_text().split() == ["example.co.uk", "other.org"]
    export([r], tmp_path / "o.csv")
    lines = (tmp_path / "o.csv").read_text(encoding="utf-8-sig").splitlines()
    assert lines[0].startswith("ip,asn,provider,hosting,domain,root_domain")
    assert lines[1].startswith("104.16.1.1,13335,Cloudflare,cdn-edge,other.org,other.org")


def test_cli_cdn_warning_and_roots(tmp_path, monkeypatch):
    monkeypatch.setitem(REGISTRY, "twosites", TwoSites)
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    monkeypatch.setenv("IPSCOPE_NO_KEYRING", "1")

    class FakeResolver:
        def __init__(self, *a, **kw):
            pass
        lookup = staticmethod(fake_info)

    monkeypatch.setattr("ipscope.engine.ASNResolver", FakeResolver)
    from ipscope.cli import app
    res = CliRunner().invoke(app, ["scan", "104.16.1.1", "-s", "twosites", "--roots"])
    assert res.exit_code == 0, res.output
    assert "Cloudflare (AS13335)" in res.output
    assert "belong to a CDN" in res.output
    assert "example.co.uk" in res.output and "shop.example.co.uk" in res.output
    res = CliRunner().invoke(app, ["scan", "104.16.1.1", "-s", "twosites", "--roots", "-q"])
    assert res.stdout.split() == ["example.co.uk", "other.org"]
