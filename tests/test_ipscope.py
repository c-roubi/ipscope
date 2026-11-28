import asyncio
import datetime as dt
import json
import ssl

import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ipscope.dns import classify
from ipscope.engine import ScanOptions, Scanner
from ipscope.export import export
from ipscope.inputs import expand_targets
from ipscope.models import DomainRecord, Status, normalize_domain
from ipscope.sources import REGISTRY, QuotaExceeded, Source, SourceContext, SourceError
from ipscope.sources.hackertarget import HackerTarget
from ipscope.sources.otx import AlienVaultOTX
from ipscope.sources.tls_cert import TLSCert


# ---------- models ----------

@pytest.mark.parametrize("raw,expected", [
    ("Example.COM.", "example.com"),
    ("*.example.com", "example.com"),
    ("  sub.example.co.uk ", "sub.example.co.uk"),
    ("bücher.de", "xn--bcher-kva.de"),
    ("_dmarc.example.com", "_dmarc.example.com"),
    ("1.2.3.4", None),
    ("localhost", None),
    ("-bad.com", None),
    ("has space.com", None),
    ("", None),
    (None, None),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_classify():
    assert classify("1.2.3.4", []) is Status.DEAD
    assert classify("1.2.3.4", ["5.6.7.8", "1.2.3.4"]) is Status.ACTIVE
    assert classify("1.2.3.4", ["5.6.7.8"]) is Status.HISTORICAL
    assert classify("2001:db8::1", ["2001:0db8:0::1"]) is Status.ACTIVE


# ---------- inputs ----------

def test_expand_targets():
    ips, warns = asyncio.run(expand_targets(
        ["8.8.8.8", "8.8.8.8", "1.1.1.0/30", "10.0.0.1", "not valid!", "# comment",
         "https://8.8.4.4/path"]
    ))
    assert ips == ["8.8.8.8", "1.1.1.1", "1.1.1.2", "8.8.4.4"]
    assert any("private" in w for w in warns)
    assert any("not valid" in w for w in warns)


def test_expand_targets_limits_and_private():
    ips, warns = asyncio.run(expand_targets(["10.0.0.0/8"], max_hosts=1024))
    assert ips == [] and "exceed" in warns[0]
    ips, _ = asyncio.run(expand_targets(["127.0.0.1"], allow_private=True))
    assert ips == ["127.0.0.1"]


# ---------- source parsers ----------

def test_hackertarget_parse():
    recs = HackerTarget.parse("a.com\nB.com\n\n1.2.3.4\n")
    assert [r.domain for r in recs] == ["a.com", "b.com"]
    assert HackerTarget.parse("No DNS A records found for 1.2.3.4") == []
    with pytest.raises(QuotaExceeded):
        HackerTarget.parse("API count exceeded - Increase Quota with Membership")
    with pytest.raises(SourceError):
        HackerTarget.parse("error check your search parameter")


def test_otx_parse():
    data = {"passive_dns": [
        {"hostname": "a.com", "record_type": "A", "first": "2020-01-01T00:00:00", "last": "2024-01-01T00:00:00"},
        {"hostname": "c.com", "record_type": "CNAME"},
        {"hostname": "bad", "record_type": "A"},
    ]}
    recs = AlienVaultOTX.parse(data)
    assert len(recs) == 1 and recs[0].domain == "a.com" and recs[0].first_seen.startswith("2020")
    assert AlienVaultOTX.parse(None) == []


# ---------- HTTP fetch with retries (local test server) ----------

def test_http_source_retries_then_succeeds():
    async def main():
        calls = {"n": 0}

        async def handler(request):
            calls["n"] += 1
            if calls["n"] == 1:
                return web.Response(status=503)
            assert request.query["q"] == "8.8.8.8"
            return web.Response(text="one.example.com\ntwo.example.com\n")

        app = web.Application()
        app.router.add_get("/reverseiplookup/", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]

        class LocalHT(HackerTarget):
            URL = f"http://127.0.0.1:{port}/reverseiplookup/"
            rate = 0

        import aiohttp
        async with aiohttp.ClientSession() as s:
            src = LocalHT(SourceContext(s, timeout=5, retries=2))
            recs = await src.lookup("8.8.8.8")
        await runner.cleanup()
        return calls["n"], [r.domain for r in recs]

    n, domains = asyncio.run(main())
    assert n == 2
    assert domains == ["one.example.com", "two.example.com"]


# ---------- TLS certificate source (local TLS server) ----------

def _make_cert(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("test.example.com"), x509.DNSName("www.test.example.com"),
            x509.DNSName("*.wild.example.org"),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_p, key_p = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    return cert_p, key_p


def test_tls_source(tmp_path):
    cert_p, key_p = _make_cert(tmp_path)

    async def main():
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cert_p, key_p)

        async def handle(reader, writer):
            try:
                await reader.read(1)
            except Exception:
                pass
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=sctx)
        port = server.sockets[0].getsockname()[1]
        # port+0 works, a closed port must be skipped silently
        src = TLSCert(SourceContext(None, timeout=5, tls_ports=[1, port]))
        recs = await src.lookup("127.0.0.1")
        server.close()
        await server.wait_closed()
        return sorted({r.domain for r in recs})

    assert asyncio.run(main()) == ["test.example.com", "wild.example.org", "www.test.example.com"]


# ---------- engine + export ----------

class FakeA(Source):
    name = "fake_a"; rate = 0
    async def _lookup(self, ip):
        return [DomainRecord("a.com", self.name, "2021-01-01", "2022-01-01"),
                DomainRecord("b.com", self.name)]


class FakeB(Source):
    name = "fake_b"; rate = 0
    async def _lookup(self, ip):
        return [DomainRecord("b.com", self.name, "2019-05-05", "2023-01-01")]


class Broken(Source):
    name = "broken"; rate = 0
    async def _lookup(self, ip):
        raise SourceError("boom")


def test_engine_merges_and_exports(tmp_path):
    reg = {c.name: c for c in (FakeA, FakeB, Broken)}
    seen = []
    scanner = Scanner(ScanOptions(sources=list(reg)), on_result=seen.append, registry=reg)
    results = asyncio.run(scanner.run(["1.2.3.4", "5.6.7.8"]))

    assert len(results) == 2 and len(seen) == 2
    r = results[0]
    assert set(r.domains) == {"a.com", "b.com"}
    b = r.domains["b.com"]
    assert b.sources == {"fake_a", "fake_b"}
    assert (b.first_seen, b.last_seen) == ("2019-05-05", "2023-01-01")
    assert r.errors == {"broken": "boom"}

    assert export(results, tmp_path / "o.txt") == 2
    assert (tmp_path / "o.txt").read_text().split() == ["a.com", "b.com"]
    assert export(results, tmp_path / "o.csv") == 4
    assert "fake_a;fake_b" in (tmp_path / "o.csv").read_text(encoding="utf-8-sig")
    export(results, tmp_path / "o.json")
    data = json.loads((tmp_path / "o.json").read_text())
    assert data[0]["errors"] == {"broken": "boom"}


def test_unknown_source_rejected():
    with pytest.raises(ValueError):
        Scanner(ScanOptions(sources=["nope"]))


def test_registry():
    assert {"hackertarget", "otx", "ptr", "tls"} <= set(REGISTRY)
    assert REGISTRY["tls"].active and not REGISTRY["otx"].active
