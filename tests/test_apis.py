"""Official-API sources, presets and subdomain lookup."""
import asyncio
import json

import aiohttp
import pytest
from aiohttp import web
from typer.testing import CliRunner

from ipscope.engine import ScanOptions, Scanner
from ipscope.sources import PRESETS, REGISTRY, KeyRejected, QuotaExceeded, SourceContext, SourceError, preset_sources
from ipscope.sources.apis import DNSRift, NetworksDB, RapidDNS, THC, WebScan
from ipscope.subdomains import CrtShSubs, DNSRiftSubs, SubSource, THCSubs, find_subdomains


# ---------- parsers ----------

def test_dnsrift_parse():
    ok = {"ip": "1.2.3.4", "domain_count": 2, "domain_list": ["a.com", "WWW.b.com"], "plan": "free"}
    assert [r.domain for r in DNSRift.parse(ok)] == ["a.com", "www.b.com"]
    assert DNSRift.parse({"ip": "1.2.3.4", "domain_count": 0, "domain_list": []}) == []
    assert DNSRift.parse({"message": "No domains found for this IP"}) == []
    with pytest.raises(QuotaExceeded):
        DNSRift.parse({"message": "Daily request limit exceeded"})
    with pytest.raises(KeyRejected):
        DNSRift.parse({"message": "Invalid API key"})
    with pytest.raises(SourceError):
        DNSRift.parse({"message": "Internal error"})


def test_other_parsers():
    recs, nxt = THC.parse({"domains": [{"domain": "x.com"}, {"domain": "y.org"}], "next_page_state": "abc"})
    assert [r.domain for r in recs] == ["x.com", "y.org"] and nxt == "abc"
    assert THC.parse({"domains": []}) == ([], None)

    good = {"status": "ok", "message": {"status": "ok", "total": 2, "data": [
        {"subdomain": "a.site.com", "type": "A", "value": "1.2.3.4"}, {"subdomain": "b.site.com"}]}}
    recs, total = RapidDNS.parse(good)
    assert [r.domain for r in recs] == ["a.site.com", "b.site.com"] and total == 2
    with pytest.raises(QuotaExceeded):
        RapidDNS.parse({"status": "ok", "message": {"status": "error", "error": "result limit exceeded"}})

    recs, total = NetworksDB.parse({"total": 45, "page": 1, "results": ["n1.com", "n2.com"]})
    assert len(recs) == 2 and total == 45
    with pytest.raises(KeyRejected):
        NetworksDB.parse({"error": "Invalid API key"})

    assert [r.domain for r in WebScan.parse([{"domain": "w.cn", "title": "x"}])] == ["w.cn"]
    assert WebScan.parse(None) == [] and WebScan.parse({"data": [{"domain": "z.cn"}]})[0].domain == "z.cn"


# ---------- HTTP behaviour ----------

async def _serve(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


def test_thc_pages_and_dnsrift_quota_switches_off():
    async def main():
        calls = {"thc": 0, "rift": 0}

        async def thc(request):
            calls["thc"] += 1
            body = await request.json()
            assert body["limit"] == 200
            if body.get("page_state") is None:
                return web.json_response({"domains": [{"domain": "p1.com"}], "next_page_state": "s2"})
            return web.json_response({"domains": [{"domain": "p2.com"}], "next_page_state": None})

        async def rift(request):
            calls["rift"] += 1
            return web.json_response({"message": "Daily request limit exceeded"})

        app = web.Application()
        app.router.add_post("/lookup", thc)
        app.router.add_get("/rip", rift)
        runner, port = await _serve(app)

        class LocalTHC(THC):
            URL = f"http://127.0.0.1:{port}/lookup"
            rate = 0

        class LocalRift(DNSRift):
            URL = f"http://127.0.0.1:{port}/rip"
            rate = 0

        reg = {"thc": LocalTHC, "dnsrift": LocalRift}
        sc = Scanner(ScanOptions(sources=["thc", "dnsrift"], concurrency=1, ip_info=False), registry=reg)
        res = await sc.run(["8.8.8.8", "8.8.4.4", "1.1.1.1"])
        await runner.cleanup()
        return res, calls, sc.stats.disabled_sources

    res, calls, disabled = asyncio.run(main())
    assert all(sorted(r.domains) == ["p1.com", "p2.com"] for r in res)   # paging followed
    assert calls["thc"] == 6 and calls["rift"] == 1                       # dnsrift asked once, then off
    assert "dnsrift" in disabled


# ---------- presets ----------

def test_presets(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    assert set(PRESETS) == {"fast", "free", "full", "offline"}
    assert preset_sources("offline", {}) == ([], False)                   # no index yet
    full, active = preset_sources("full", {})
    assert active and "rapiddns" not in full and "dnsrift" in full and "tls" not in full
    full, _ = preset_sources("full", {"rapiddns": ["k"]})
    assert "rapiddns" in full
    fast, active = preset_sources("fast", {})
    assert fast == ["dnsrift", "internetdb", "ptr"] and not active
    assert all(n in REGISTRY for p in PRESETS.values() for n in p["sources"] if n != "*")


def test_cli_preset(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    monkeypatch.setenv("IPSCOPE_NO_KEYRING", "1")
    from ipscope.cli import app
    res = CliRunner().invoke(app, ["scan", "8.8.8.8", "--preset", "offline"])
    assert res.exit_code == 2 and "no usable sources" in res.output
    res = CliRunner().invoke(app, ["scan", "8.8.8.8", "--preset", "nope"])
    assert res.exit_code == 2 and "Unknown preset" in res.output


# ---------- subdomains ----------

def test_subdomain_parsers():
    assert DNSRiftSubs.parse({"subdomains": ["a.ex.com", "ex.com", "evil.com", "b.EX.com"]}, "ex.com") == \
        ["a.ex.com", "ex.com", "b.ex.com"]
    assert DNSRiftSubs.parse({"message": "No subdomains found"}, "ex.com") == []
    names, nxt = THCSubs.parse({"domains": [{"domain": "m.ex.com"}, {"domain": "other.org"}],
                                "next_page_state": "t"}, "ex.com")
    assert names == ["m.ex.com"] and nxt == "t"
    crt = [{"name_value": "*.ex.com\nwww.ex.com"}, {"name_value": "mail.ex.com"}, {"name_value": "notex.com"}]
    assert CrtShSubs.parse(crt, "ex.com") == ["ex.com", "www.ex.com", "mail.ex.com"]


class FakeA(SubSource):
    name = "fa"; rate = 0
    async def subdomains(self, domain):
        return [f"www.{domain}", f"mail.{domain}"]


class FakeB(SubSource):
    name = "fb"; rate = 0
    async def subdomains(self, domain):
        return [f"www.{domain}", f"api.{domain}"]


class FakeBroken(SubSource):
    name = "fx"; rate = 0
    async def subdomains(self, domain):
        raise SourceError("down")


def test_find_subdomains_merges(monkeypatch):
    reg = {c.name: c for c in (FakeA, FakeB, FakeBroken)}
    results, skipped = asyncio.run(find_subdomains(["https://Example.com/path", "bad domain!"],
                                                   ["fa", "fb", "fx"], registry=reg))
    [r] = results
    assert r.domain == "example.com" and skipped == []
    assert r.names == {"www.example.com": {"fa", "fb"}, "mail.example.com": {"fa"}, "api.example.com": {"fb"}}
    assert r.errors == {"fx": "down"}


def test_cli_subdomains(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    monkeypatch.setenv("IPSCOPE_NO_KEYRING", "1")
    import ipscope.subdomains as subs
    monkeypatch.setattr(subs, "SUB_REGISTRY", {"fa": FakeA, "fb": FakeB})
    monkeypatch.setattr(subs, "DEFAULT_SUB_SOURCES", ["fa", "fb"])
    from ipscope.cli import app
    run = CliRunner().invoke
    res = run(app, ["subdomains", "example.com", "-q"])
    assert res.exit_code == 0, res.output
    assert res.stdout.split() == ["api.example.com", "mail.example.com", "www.example.com"]
    out = tmp_path / "s.csv"
    res = run(app, ["subdomains", "example.com", "-o", str(out)])
    assert "Saved 3" in res.output
    assert out.read_text(encoding="utf-8-sig").splitlines()[1].startswith("example.com,api.example.com,fb")
    res = run(app, ["subdomains", "example.com", "-s", "nope"])
    assert res.exit_code == 2


def test_gui_meta_has_presets(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    monkeypatch.setenv("IPSCOPE_NO_KEYRING", "1")
    from ipscope.gui.api import Api
    meta = Api().get_meta()
    json.dumps(meta)
    assert meta["presets"]["full"]["active"] and "dnsrift" in meta["presets"]["fast"]["sources"]
    names = {s["name"] for s in meta["sources"]}
    assert {"dnsrift", "thc", "rapiddns", "networksdb", "webscan"} <= names
