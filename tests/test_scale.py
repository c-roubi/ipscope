"""Behaviour needed for big scans: streaming, paging, migration, circuit breaker, async DNS."""
import asyncio
import json
import time

import pytest

from ipscope.dns import AsyncResolver, classify
from ipscope.engine import AllSourcesDisabled, ScanOptions, Scanner
from ipscope.export import export_scan
from ipscope.models import DomainRecord, IPResult, Status
from ipscope.sources import KeyRejected, QuotaExceeded, RateLimited, Source
from ipscope.storage import Store


def _result(ip, names, status=Status.UNKNOWN, info=None):
    r = IPResult(ip, info=info or {})
    for n in names:
        r.add(DomainRecord(n, "src"))
        r.domains[n].status = status
        r.domains[n].root = ".".join(n.split(".")[-2:])
    return r


# ---------- storage: paging, search, streaming ----------

def test_paging_and_queries(tmp_path):
    with Store(tmp_path / "db") as st:
        ips = [f"5.5.5.{i}" for i in range(1, 6)]
        sid = st.create_scan(ips, {})
        for i, ip in enumerate(ips):
            names = [f"h{j}.site{i}.com" for j in range(100)]
            st.save_result(sid, _result(ip, names, Status.ACTIVE if i % 2 else Status.DEAD,
                                        {"provider": "Hetzner", "asn": 24940, "category": "cdn" if i == 0 else "hosting"}))
        s = st.summary(sid)
        assert (s["ips"], s["rows"], s["domains"], s["roots"], s["cdn_ips"]) == (5, 500, 500, 5, 1)
        assert s["active"] == 200 and s["cdn_providers"] == ["Hetzner"]

        rows, total = st.query_domains(sid, offset=0, limit=50)
        assert total == 500 and len(rows) == 50 and rows[0]["domain"] == "h0.site0.com"
        rows2, _ = st.query_domains(sid, offset=50, limit=50)
        assert not {r["domain"] for r in rows} & {r["domain"] for r in rows2}       # pages don't overlap
        assert st.query_domains(sid, status="active")[1] == 200
        assert st.query_domains(sid, ip="5.5.5.2")[1] == 100
        assert st.query_domains(sid, search="h99.")[1] == 5
        assert st.query_domains(sid, search="100%_")[1] == 0                         # LIKE wildcards escaped
        assert st.status_counts(sid) == {"active": 200, "dead": 300, "all": 500}
        roots, rtotal = st.query_roots(sid, limit=2)
        assert rtotal == 5 and roots[0]["names"] == 100 and len(roots[0]["examples"]) == 4
        assert len(st.domain_names(sid, roots=True)) == 5
        top, n = st.list_ips(sid, order="domains", limit=2)
        assert n == 5 and top[0]["n_domains"] == 100
        assert st.list_ips(sid, search="24940")[1] == 5

        streamed = list(st.iter_results(sid))
        assert [r.ip for r in streamed] == ips and len(streamed[3].domains) == 100

        n = export_scan(st, sid, tmp_path / "a.txt", only_active=True)
        assert n == 200
        n = export_scan(st, sid, tmp_path / "a.json")
        assert n == 500 and len(json.loads((tmp_path / "a.json").read_text())) == 5
        assert st.delete_scan(sid) and st.query_domains(sid)[1] == 0                # cascade


def test_migrates_scans_from_older_versions(tmp_path):
    """v0.2-0.4 stored domains inside scan_ips.result; they must still open."""
    with Store(tmp_path / "db") as st:
        sid = st.create_scan(["1.1.1.1", "2.2.2.2"], {})
        old = _result("1.1.1.1", ["a.com", "b.com"]).to_dict()
        st.db.execute("UPDATE scan_ips SET done=1, v2=0, result=? WHERE scan_id=? AND ip='1.1.1.1'",
                      (json.dumps(old), sid))
        st.db.commit()
        assert st.query_domains(sid)[1] == 2
        assert [r.ip for r in st.results(sid)] == ["1.1.1.1"]
        assert st.db.execute("SELECT v2 FROM scan_ips WHERE ip='1.1.1.1'").fetchone()[0] == 1


# ---------- engine: circuit breaker, flat memory ----------

class Fine(Source):
    name = "fine"; rate = 0
    async def _lookup(self, ip):
        return [DomainRecord(f"x-{ip.replace('.', '-')}.com", self.name)]


class OutOfQuota(Source):
    name = "quota"; rate = 0
    calls = 0
    async def _lookup(self, ip):
        type(self).calls += 1
        raise QuotaExceeded("daily quota exceeded")


class Throttled(Source):
    name = "throttled"; rate = 0
    calls = 0
    async def _lookup(self, ip):
        type(self).calls += 1
        raise RateLimited("HTTP 429")


def test_quota_switches_source_off():
    OutOfQuota.calls = 0
    events = []
    reg = {c.name: c for c in (Fine, OutOfQuota)}
    sc = Scanner(ScanOptions(sources=["fine", "quota"], concurrency=1, ip_info=False), registry=reg,
                 on_event=lambda lvl, msg: events.append(msg))
    res = asyncio.run(sc.run([f"8.8.8.{i}" for i in range(1, 21)]))
    assert OutOfQuota.calls == 1                       # not hammered 20 times
    assert sc.stats.disabled_sources == {"quota": "daily quota exceeded"}
    assert sum(1 for r in res if "quota" in r.errors) == 1
    assert all(r.domains for r in res)                 # the other source kept working
    assert len(events) == 1 and "switched off" in events[0]


def test_rate_limit_needs_strikes_and_all_disabled_stops():
    Throttled.calls = 0
    reg = {"throttled": Throttled}
    sc = Scanner(ScanOptions(sources=["throttled"], concurrency=1, ip_info=False), registry=reg)
    with pytest.raises(AllSourcesDisabled):
        asyncio.run(sc.run([f"8.8.8.{i}" for i in range(1, 30)]))
    assert Throttled.calls == 3


def test_collect_false_keeps_nothing():
    seen = []
    sc = Scanner(ScanOptions(sources=["fine"], ip_info=False), registry={"fine": Fine}, on_result=seen.append)
    assert asyncio.run(sc.run([f"8.8.{i // 250}.{i % 250}" for i in range(500)], collect=False)) == []
    assert len(seen) == 500 and len({r.ip for r in seen}) == 500   # every IP exactly once


# ---------- async DNS ----------

def test_async_resolver_cache_dedupe_and_failures(monkeypatch):
    calls = []

    async def fake_lookup(self, domain):
        calls.append(domain)
        await asyncio.sleep(0.05)
        return {"ok.com": ["1.2.3.4"], "gone.com": []}.get(domain)   # None = lookup failed

    monkeypatch.setattr(AsyncResolver, "_lookup", fake_lookup)

    async def main():
        r = AsyncResolver(concurrency=500)
        t = time.time()
        out = await asyncio.gather(*[r.resolve("ok.com") for _ in range(50)],
                                   r.resolve("gone.com"), r.resolve("timeout.com"))
        took = time.time() - t
        again = await r.resolve("ok.com")
        failed_again = await r.resolve("timeout.com")
        return out, took, again, failed_again

    out, took, again, _ = asyncio.run(main())
    assert out[0] == ["1.2.3.4"] and out[50] == [] and out[51] is None
    assert calls.count("ok.com") == 1          # 50 concurrent asks -> one query (deduped), then cached
    assert calls.count("timeout.com") == 2     # failures are not cached
    assert took < 0.5 and again == ["1.2.3.4"]
    assert classify("1.2.3.4", None) is Status.UNKNOWN
    assert classify("1.2.3.4", []) is Status.DEAD


def test_async_resolver_parallelism(monkeypatch):
    async def slow(self, domain):
        await asyncio.sleep(0.1)
        return ["9.9.9.9"]

    monkeypatch.setattr(AsyncResolver, "_lookup", slow)

    async def main():
        r = AsyncResolver(concurrency=200)
        t = time.time()
        await asyncio.gather(*(r.resolve(f"d{i}.com") for i in range(1000)))
        return time.time() - t

    assert asyncio.run(main()) < 1.5            # 1000 x 100ms lookups, 200 at a time ~0.5s
