import asyncio
import json
import os
import stat
import time

import aiohttp
import pytest
from aiohttp import web
from typer.testing import CliRunner

from ipscope.engine import ScanOptions, Scanner
from ipscope.keys import KeyStore, mask
from ipscope.models import DomainRecord, IPResult, Status
from ipscope.sources import REGISTRY, Source, SourceContext, default_sources
from ipscope.sources.hackertarget import HackerTarget
from ipscope.sources.securitytrails import SecurityTrails
from ipscope.sources.shodan import InternetDB, Shodan
from ipscope.sources.virustotal import VirusTotal
from ipscope.storage import Store


# ---------- helpers ----------

async def _serve(routes):
    app = web.Application()
    for method, path, handler in routes:
        app.router.add_route(method, path, handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


# ---------- storage ----------

def test_cache_roundtrip_and_ttl(tmp_path):
    with Store(tmp_path / "db.sqlite") as s:
        assert s.cache_get("x", "1.2.3.4", 60) is None
        s.cache_put("x", "1.2.3.4", [DomainRecord("a.com", "x", "2020", "2021")])
        hit = s.cache_get("x", "1.2.3.4", 60)
        assert hit == [DomainRecord("a.com", "x", "2020", "2021")]
        s.cache_put("x", "9.9.9.9", [])
        assert s.cache_get("x", "9.9.9.9", 60) == []          # empty results are cached too
        s.db.execute("UPDATE cache SET fetched_at=?", (time.time() - 120,))
        assert s.cache_get("x", "1.2.3.4", 60) is None        # expired
        assert s.cache_stats() == [("x", 2)]
        assert s.cache_clear(older_than=60) == 2


def test_scan_lifecycle(tmp_path):
    with Store(tmp_path / "db.sqlite") as s:
        sid = s.create_scan(["1.1.1.1", "2.2.2.2", "3.3.3.3"], {"sources": ["a"]}, "test")
        r = IPResult("2.2.2.2")
        r.add(DomainRecord("b.com", "a"))
        r.domains["b.com"].status = Status.ACTIVE
        s.save_result(sid, r)
        assert s.pending_ips(sid) == ["1.1.1.1", "3.3.3.3"]
        assert s.latest_resumable() == sid
        back = s.results(sid)
        assert back[0].ip == "2.2.2.2" and back[0].domains["b.com"].status is Status.ACTIVE
        info = s.get_scan(sid)
        assert (info["done"], info["total"], info["label"]) == (1, 3, "test")
        s.set_status(sid, "done")
        assert s.latest_resumable() is None
        assert s.delete_scan(sid) and s.get_scan(sid) is None


# ---------- keys ----------

def test_keystore_file_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("IPSCOPE_VIRUSTOTAL_KEY", raising=False)
    ks = KeyStore(home=tmp_path, use_keyring=False)
    assert ks.get("virustotal") == []
    ks.set("virustotal", ["k1"])
    assert ks.add("virustotal", "k2") == 2
    assert ks.add("virustotal", "k2") == 2                    # no duplicates
    assert ks.get("virustotal") == ["k1", "k2"]
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "keys.json").stat().st_mode) == 0o600
    assert ks.resolve("virustotal", "IPSCOPE_VIRUSTOTAL_KEY") == (["k1", "k2"], "store")
    monkeypatch.setenv("IPSCOPE_VIRUSTOTAL_KEY", "envkey, env2")
    assert ks.resolve("virustotal", "IPSCOPE_VIRUSTOTAL_KEY") == (["envkey", "env2"], "env:IPSCOPE_VIRUSTOTAL_KEY")
    assert ks.delete("virustotal") and not ks.delete("virustotal")
    assert mask("abcdefghijklmnop") == "abcd…mnop"


def test_default_sources_include_keyed_when_configured():
    d = default_sources({})
    assert "virustotal" not in d and "internetdb" in d and "tls" not in d
    assert "virustotal" in default_sources({"virustotal": ["k"]})


# ---------- parsers ----------

def test_virustotal_parse():
    data = {"data": [{"attributes": {"host_name": "A.com", "date": 1700000000}},
                     {"attributes": {"host_name": "1.2.3.4"}}],
            "meta": {"cursor": "abc"}}
    recs, cursor = VirusTotal.parse(data)
    assert [r.domain for r in recs] == ["a.com"] and recs[0].last_seen.startswith("2023-11-14")
    assert cursor == "abc"
    assert VirusTotal.parse({"data": []}) == ([], None)


def test_securitytrails_parse():
    recs, pages = SecurityTrails.parse({"records": [{"hostname": "x.com"}], "meta": {"total_pages": 3}})
    assert [r.domain for r in recs] == ["x.com"] and pages == 3


def test_shodan_parse():
    data = {
        "hostnames": ["ec2-1.compute.amazonaws.com"],
        "domains": ["amazonaws.com"],
        "data": [
            {"hostnames": ["shop.example.com"], "http": {"host": "www.example.com"},
             "ssl": {"cert": {"subject": {"CN": "*.example.com"}}}},
            {"http": {"host": "1.2.3.4"}},
        ],
    }
    names = sorted(r.domain for r in Shodan.parse(data))
    assert names == ["ec2-1.compute.amazonaws.com", "example.com", "shop.example.com", "www.example.com"]
    assert [r.domain for r in InternetDB.parse({"hostnames": ["a.org", "a.org"]})] == ["a.org"]
    assert InternetDB.parse(None) == []


# ---------- HTTP behaviour: key rotation, pagination, POST ----------

def test_key_rotation_on_401_and_429():
    async def main():
        seen = []

        async def handler(request):
            key = request.headers.get("x-apikey")
            seen.append(key)
            if key == "bad":
                return web.Response(status=401)
            if key == "limited":
                return web.Response(status=429)
            cursor = request.query.get("cursor")
            if cursor is None:
                return web.json_response({"data": [{"attributes": {"host_name": "p1.com"}}],
                                          "meta": {"cursor": "next"}})
            return web.json_response({"data": [{"attributes": {"host_name": "p2.com"}}]})

        runner, port = await _serve([("GET", "/{ip}", handler)])

        class LocalVT(VirusTotal):
            URL = f"http://127.0.0.1:{port}/{{ip}}"
            rate = 0
            backoff = 0

        async with aiohttp.ClientSession() as s:
            ctx = SourceContext(s, timeout=5, retries=1,
                                keys={"virustotal": ["bad", "limited", "good"]})
            src = LocalVT(ctx)
            recs = await src.lookup("8.8.8.8")
        await runner.cleanup()
        return seen, [r.domain for r in recs], src.api_key

    seen, domains, current = asyncio.run(main())
    assert seen[:3] == ["bad", "limited", "good"]
    assert domains == ["p1.com", "p2.com"]   # followed the cursor
    assert current == "good"


def test_all_keys_rejected_is_an_error():
    async def main():
        async def handler(request):
            return web.Response(status=403)

        runner, port = await _serve([("GET", "/{ip}", handler)])

        class LocalShodan(Shodan):
            URL = f"http://127.0.0.1:{port}/{{ip}}"
            rate = 0

        async with aiohttp.ClientSession() as s:
            src = LocalShodan(SourceContext(s, timeout=5, keys={"shodan": ["a", "b"]}))
            with pytest.raises(Exception) as e:
                await src.lookup("8.8.8.8")
        await runner.cleanup()
        return str(e.value)

    assert "API key rejected" in asyncio.run(main())


def test_securitytrails_post_and_pages():
    async def main():
        bodies = []

        async def handler(request):
            assert request.headers["APIKEY"] == "k"
            bodies.append(await request.json())
            page = int(request.query["page"])
            return web.json_response({"records": [{"hostname": f"p{page}.com"}],
                                      "meta": {"total_pages": 2}})

        runner, port = await _serve([("POST", "/list", handler)])

        class LocalST(SecurityTrails):
            URL = f"http://127.0.0.1:{port}/list"
            rate = 0

        async with aiohttp.ClientSession() as s:
            recs = await LocalST(SourceContext(s, timeout=5, keys={"securitytrails": ["k"]})).lookup("8.8.8.8")
        await runner.cleanup()
        return bodies, [r.domain for r in recs]

    bodies, domains = asyncio.run(main())
    assert bodies[0] == {"filter": {"ipv4": "8.8.8.8"}}
    assert domains == ["p1.com", "p2.com"]


def test_hackertarget_quota_rotates_key():
    async def main():
        async def handler(request):
            if request.query.get("apikey") == "used":
                return web.Response(text="API count exceeded - Increase Quota with Membership")
            return web.Response(text="ok.example.com\n")

        runner, port = await _serve([("GET", "/r/", handler)])

        class LocalHT(HackerTarget):
            URL = f"http://127.0.0.1:{port}/r/"
            rate = 0

        async with aiohttp.ClientSession() as s:
            recs = await LocalHT(SourceContext(s, timeout=5, keys={"hackertarget": ["used", "fresh"]})).lookup("8.8.8.8")
        await runner.cleanup()
        return [r.domain for r in recs]

    assert asyncio.run(main()) == ["ok.example.com"]


# ---------- engine: cache + skipping keyless sources ----------

CALLS = {"n": 0}


class Counting(Source):
    name = "counting"; rate = 0
    async def _lookup(self, ip):
        CALLS["n"] += 1
        return [DomainRecord(f"site-{ip.replace('.', '-')}.com", self.name)]


class NeedsKey(Source):
    name = "needskey"; rate = 0; requires_key = True; key_env = "IPSCOPE_NEEDSKEY_TEST"
    async def _lookup(self, ip):
        raise AssertionError("must not run without a key")


def test_engine_uses_cache_and_skips_keyless(tmp_path, monkeypatch):
    monkeypatch.delenv("IPSCOPE_NEEDSKEY_TEST", raising=False)
    CALLS["n"] = 0
    reg = {"counting": Counting, "needskey": NeedsKey}
    with Store(tmp_path / "db.sqlite") as store:
        opts = ScanOptions(sources=["counting", "needskey"])
        s1 = Scanner(opts, registry=reg, store=store)
        r1 = asyncio.run(s1.run(["1.1.1.1", "2.2.2.2"]))
        assert CALLS["n"] == 2 and s1.stats.skipped_sources == ["needskey"]
        s2 = Scanner(opts, registry=reg, store=store)
        r2 = asyncio.run(s2.run(["1.1.1.1", "2.2.2.2"]))
        assert CALLS["n"] == 2 and s2.stats.cache_hits == 2     # served from cache
        assert [r.domains.keys() for r in r1] == [r.domains.keys() for r in r2]
        s3 = Scanner(ScanOptions(sources=["counting"], use_cache=False), registry=reg, store=store)
        asyncio.run(s3.run(["1.1.1.1"]))
        assert CALLS["n"] == 3

    with pytest.raises(ValueError):
        asyncio.run(Scanner(ScanOptions(sources=["needskey"]), registry=reg).run(["1.1.1.1"]))


# ---------- CLI end-to-end ----------

def test_cli_scan_history_show_resume(tmp_path, monkeypatch):
    monkeypatch.setitem(REGISTRY, "counting", Counting)
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    monkeypatch.setenv("IPSCOPE_NO_KEYRING", "1")   # never touch the real OS keyring in tests
    for cls in REGISTRY.values():
        if cls.key_env:
            monkeypatch.delenv(cls.key_env, raising=False)
    from ipscope.cli import app
    runner = CliRunner()

    res = runner.invoke(app, ["scan", "8.8.8.8", "-s", "counting", "-q", "--label", "first"])
    assert res.exit_code == 0, res.output
    assert "site-8-8-8-8.com" in res.stdout

    res = runner.invoke(app, ["history"])
    assert "first" in res.stdout and "done" in res.stdout

    out_file = tmp_path / "r.json"
    res = runner.invoke(app, ["show", "1", "-o", str(out_file)])
    assert res.exit_code == 0
    assert json.loads(out_file.read_text())[0]["domains"][0]["domain"] == "site-8-8-8-8.com"

    # simulate a scan that was interrupted after the first IP
    with Store(tmp_path / "ipscope.db") as s:
        sid = s.create_scan(["1.1.1.1", "9.9.9.9"], ScanOptions(sources=["counting"]).to_dict())
        done = IPResult("1.1.1.1")
        done.add(DomainRecord("old.com", "counting"))
        s.save_result(sid, done)
        s.set_status(sid, "interrupted")

    res = runner.invoke(app, ["resume", "-q"])
    assert res.exit_code == 0, res.output
    assert "old.com" in res.stdout and "site-9-9-9-9.com" in res.stdout
    with Store(tmp_path / "ipscope.db") as s:
        assert s.get_scan(sid)["status"] == "done"

    res = runner.invoke(app, ["resume"])
    assert res.exit_code == 1  # nothing left

    res = runner.invoke(app, ["keys", "set", "virustotal", "abcdefghijkl1234"])
    assert res.exit_code == 0
    res = runner.invoke(app, ["keys", "list"])
    assert "abcd…1234" in res.stdout
    res = runner.invoke(app, ["keys", "set", "ptr", "x"])
    assert res.exit_code == 2

    res = runner.invoke(app, ["cache", "stats"])
    assert "counting" in res.stdout
    res = runner.invoke(app, ["cache", "clear"])
    assert res.exit_code == 0
