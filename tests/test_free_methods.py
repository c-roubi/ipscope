"""http source, extended tls source (incl. SMTP STARTTLS) and the local index."""
import asyncio
import datetime as dt
import gzip
import json
import ssl
import time

import aiohttp
import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ipscope.dns import AsyncResolver
from ipscope.engine import ScanOptions, Scanner
from ipscope.index import LocalIndex, detect_format
from ipscope.sources import REGISTRY, SourceContext, default_sources
from ipscope.sources.http_grab import HTTPGrab, self_references
from ipscope.sources.tls_cert import TLSCert


# ---------- http source ----------

def test_self_references():
    body = b'''<html><head>
      <link href="https://www.shop-one.com/" rel="canonical">
      <meta content="https://og.shop-one.com/page" property="og:url">
      <base href='//base.shop-one.com/'>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/x.css">
      <a href="https://facebook.com/shop">fb</a>
      <link rel="canonical" href="http://5.5.5.5/">
    </head></html>'''
    assert self_references(body, "http://5.5.5.5/") == ["www.shop-one.com", "og.shop-one.com", "base.shop-one.com"]


async def _serve(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


def test_http_grab_redirect_and_canonical():
    async def main():
        async def home(r):
            raise web.HTTPFound("/landing")                                 # same-IP redirect: follow it

        async def landing(r):
            return web.Response(text='<link rel="canonical" href="https://main-site.ps/">', content_type="text/html")

        async def moved(r):
            raise web.HTTPMovedPermanently("https://www.redirected.com/")

        a = web.Application()
        a.router.add_get("/", home)
        a.router.add_get("/landing", landing)
        b = web.Application()
        b.router.add_get("/", moved)
        ra, pa = await _serve(a)
        rb, pb = await _serve(b)

        class Local(HTTPGrab):
            PORTS = [(pa, "http"), (pb, "http"), (1, "http")]   # port 1: closed, must be ignored

        async with aiohttp.ClientSession() as s:
            recs = await Local(SourceContext(s, timeout=5)).lookup("127.0.0.1")
        await ra.cleanup()
        await rb.cleanup()
        return sorted(r.domain for r in recs)

    assert asyncio.run(main()) == ["main-site.ps", "www.redirected.com"]


# ---------- tls source: STARTTLS on SMTP ----------

def _cert(tmp_path, names):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    c, k = tmp_path / "c.pem", tmp_path / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return c, k


def test_tls_smtp_starttls_and_banner(tmp_path, monkeypatch):
    c, k = _cert(tmp_path, ["mail.hosting-co.net", "webmail.hosting-co.net"])

    async def main():
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(c, k)

        async def smtp(reader, writer):
            writer.write(b"220 mx1.hosting-co.net ESMTP Postfix\r\n")
            await writer.drain()
            await reader.readline()                                   # EHLO
            writer.write(b"250-mx1.hosting-co.net\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
            await writer.drain()
            await reader.readline()                                   # STARTTLS
            writer.write(b"220 2.0.0 Ready to start TLS\r\n")
            await writer.drain()
            try:
                await writer.start_tls(sctx)
                await reader.read(1)
            except Exception:
                pass
            writer.close()

        server = await asyncio.start_server(smtp, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr("ipscope.sources.tls_cert.STARTTLS_SMTP", {port})
        src = TLSCert(SourceContext(None, timeout=5, tls_ports=[port, 1]))
        recs = await src.lookup("127.0.0.1")
        server.close()
        await server.wait_closed()
        return sorted(r.domain for r in recs)

    assert asyncio.run(main()) == ["mail.hosting-co.net", "mx1.hosting-co.net", "webmail.hosting-co.net"]


def test_tls_ports_run_in_parallel():
    """6 ports that accept but never finish the handshake must cost one timeout, not six."""
    async def main():
        async def silent(reader, writer):
            await asyncio.sleep(10)
        servers = [await asyncio.start_server(silent, "127.0.0.1", 0) for _ in range(6)]
        ports = [srv.sockets[0].getsockname()[1] for srv in servers]
        src = TLSCert(SourceContext(None, timeout=1.5, tls_ports=ports))
        t = time.time()
        out = await src.lookup("127.0.0.1")
        took = time.time() - t
        for srv in servers:
            srv.close()
        return out, took

    out, took = asyncio.run(main())
    assert out == [] and took < 3.0


def test_placeholder_names_filtered():
    from ipscope.models import is_placeholder
    for junk in ("default.domain", "localhost.localdomain", "router.lan", "traefik.default", "x.ingress.local",
                 "foo.svc.cluster.local"):
        assert is_placeholder(junk), junk
    for real in ("shop.example.co.uk", "mail.hosting-co.net", "local-news.ps", "test-site.com"):
        assert not is_placeholder(real), real


# ---------- local index ----------

@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    monkeypatch.setenv("IPSCOPE_NO_KEYRING", "1")
    return tmp_path


FAKE_DNS = {"shop.example.com": ["5.5.5.5"], "blog.example.com": ["5.5.5.5", "2001:db8::5"],
            "other.org": ["6.6.6.6"], "gone.net": []}


@pytest.fixture
def fake_dns(monkeypatch):
    async def lookup(self, domain):
        await asyncio.sleep(0.001)
        return FAKE_DNS.get(domain)          # unknown -> None (lookup failed)
    monkeypatch.setattr(AsyncResolver, "_lookup", lookup)


def test_detect_format():
    assert detect_format('{"name": "a.com", "type": "a"}') == "fdns"
    assert detect_format("example.com. 172800 in ns ns1.example.net.") == "zone"
    assert detect_format("example.com") == "plain"


def test_index_import_resolve_lookup(home, fake_dns):
    plain = home / "list.txt"
    plain.write_text("# my list\nshop.example.com\nblog.example.com\nSHOP.example.com\nnot a domain\nbroken.test\n")
    zone = home / "com.zone.gz"
    with gzip.open(zone, "wt") as f:
        f.write("; zone\n$ORIGIN com.\nother.org. 172800 in ns ns1.x.net.\nother.org. 172800 in ns ns2.x.net.\n"
                "gone.net. 86400 in ns ns1.y.net.\n")
    fdns = home / "fdns_a.json.gz"
    with gzip.open(fdns, "wt") as f:
        for rec in [{"timestamp": "1700000000", "name": "fdns-site.com", "type": "a", "value": "7.7.7.7"},
                    {"timestamp": "1700000000", "name": "www.fdns-site.com", "type": "cname", "value": "x"},
                    {"timestamp": "1700000000", "name": "v6.fdns-site.com", "type": "aaaa", "value": "2001:db8::7"}]:
            f.write(json.dumps(rec) + "\n")

    with LocalIndex() as idx:
        r1 = idx.import_file(plain)
        assert r1["format"] == "plain" and r1["names"] == 3          # deduped, invalid dropped
        r2 = idx.import_file(zone)
        assert r2["format"] == "zone" and r2["names"] == 2
        r3 = idx.import_file(fdns)
        assert r3["format"] == "fdns" and r3["records"] == 2
        assert idx.lookup("7.7.7.7")[0][0] == "fdns-site.com"        # FDNS needs no resolving
        assert idx.pending_count() == 5

        st = asyncio.run(idx.resolve(concurrency=50, chunk=2))
        assert (st["done"], st["ok"], st["nx"], st["failed"]) == (5, 3, 1, 1)
        assert [n for n, _ in idx.lookup("5.5.5.5")] == ["blog.example.com", "shop.example.com"]
        assert [n for n, _ in idx.lookup("2001:db8::5")] == ["blog.example.com"]
        s = idx.stats()
        assert (s["names"], s["resolved"], s["nxdomain"], s["failed"], s["pending"]) == (7, 5, 1, 1, 0)

        FAKE_DNS["broken.test"] = ["5.5.5.5"]                        # it works now
        st = asyncio.run(idx.resolve(retry_failed=True))
        assert st["done"] == 1 and len(idx.lookup("5.5.5.5")) == 3
        FAKE_DNS["shop.example.com"] = ["9.9.9.9"]                   # site moved
        asyncio.run(idx.resolve(refresh_days=0))
        assert "shop.example.com" not in [n for n, _ in idx.lookup("5.5.5.5")]
        assert [n for n, _ in idx.lookup("9.9.9.9")] == ["shop.example.com"]
    FAKE_DNS["shop.example.com"] = ["5.5.5.5"]
    FAKE_DNS.pop("broken.test")


def test_local_source_in_scans(home, fake_dns):
    assert "local" not in default_sources({})
    assert not REGISTRY["local"](SourceContext(None)).available
    with LocalIndex() as idx:
        idx.add_names(["shop.example.com", "blog.example.com"])
        asyncio.run(idx.resolve())
    assert default_sources({})[0] == "local"
    sc = Scanner(ScanOptions(sources=["local"], ip_info=False))
    [r] = asyncio.run(sc.run(["5.5.5.5"]))
    assert sorted(r.domains) == ["blog.example.com", "shop.example.com"]
    assert r.domains["shop.example.com"].sources == {"local"} and r.domains["shop.example.com"].last_seen


def test_cli_index_commands(home, fake_dns):
    from typer.testing import CliRunner
    from ipscope.cli import app
    f = home / "d.txt"
    f.write_text("shop.example.com\nother.org\n")
    run = CliRunner().invoke
    res = run(app, ["index", "build", str(f)])
    assert res.exit_code == 0, res.output
    assert "2 new names" in res.output and "2 resolved" in res.output
    res = run(app, ["index", "lookup", "6.6.6.6"])
    assert res.stdout.strip() == "other.org"
    res = run(app, ["index", "stats"])
    assert "Resolved" in res.stdout
    res = run(app, ["scan", "5.5.5.5", "-s", "local", "-q", "--no-ip-info"])
    assert res.stdout.split() == ["shop.example.com"]


def test_gui_index_job(home, fake_dns):
    from ipscope.gui.api import Api
    api = Api()
    f = home / "d.txt"
    f.write_text("shop.example.com\nblog.example.com\ngone.net\n")
    api.index_import([str(f)], concurrency=20)
    end = time.time() + 10
    while api.index_state()["state"] == "running" and time.time() < end:
        time.sleep(0.05)
    st = api.index_state()
    assert st["state"] == "done", st["logs"]
    assert any("3 new names" in l["msg"] for l in st["logs"])
    s = api.index_stats()
    assert s["resolved"] == 2 and s["nxdomain"] == 1 and s["records"] == 3
    meta = next(x for x in api.get_meta()["sources"] if x["name"] == "local")
    assert meta["default"] and not meta["needs_index"]


def test_fdns_only_filter(home):
    fdns = home / "f.json.gz"
    with gzip.open(fdns, "wt") as f:
        for i, ip in enumerate(["5.9.1.1", "5.9.200.7", "8.8.8.8", "2001:db8::1", "bad"]):
            f.write(json.dumps({"timestamp": "1700000000", "name": f"s{i}.site.com", "type": "a", "value": ip}) + "\n")
    with LocalIndex() as idx:
        r = idx.import_file(fdns, only=["5.9.0.0/16", "2001:db8::/32"])
        assert r["records"] == 3
        assert idx.lookup("8.8.8.8") == [] and idx.lookup("5.9.200.7")[0][0] == "s1.site.com"
