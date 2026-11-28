"""first-hit, roots-only, skip-scanned and hide-sources."""
import asyncio
import time

import pytest

from ipscope.engine import ScanOptions, Scanner, collapse_to_roots
from ipscope.models import DomainRecord, IPResult, Status
from ipscope.sources import REGISTRY, Source, SourceError
from ipscope.storage import Store

CALLS = []


def _src(name, names=(), fail=False):
    async def _lookup(self, ip):
        CALLS.append(name)
        if fail:
            raise SourceError("down")
        return [DomainRecord(n, name) for n in names]
    return type(name, (Source,), {"name": name, "rate": 0, "_lookup": _lookup})


def test_first_hit_stops_at_first_match():
    CALLS.clear()
    reg = {"local": _src("local"), "dnsrift": _src("dnsrift", fail=True),
           "thc": _src("thc", ["a.com", "b.com"]), "otx": _src("otx", ["c.com"])}
    sc = Scanner(ScanOptions(sources=["otx", "thc", "dnsrift", "local"], first_hit=True, ip_info=False), registry=reg)
    [r] = asyncio.run(sc.run(["8.8.8.8"]))
    assert CALLS == ["local", "dnsrift", "thc"]          # cascade order, otx never asked
    assert sorted(r.domains) == ["a.com", "b.com"] and r.errors == {"dnsrift": "down"}

    CALLS.clear()
    sc = Scanner(ScanOptions(sources=["otx", "thc"], ip_info=False), registry=reg)
    [r] = asyncio.run(sc.run(["8.8.8.8"]))
    assert sorted(CALLS) == ["otx", "thc"] and len(r.domains) == 3   # normal mode asks everyone


def test_collapse_to_roots():
    r = IPResult("5.5.5.5")
    for name, src, status in [("shop.ex.com", "a", Status.DEAD), ("www.ex.com", "b", Status.ACTIVE),
                              ("ex.com", "a", Status.HISTORICAL), ("blog.other.org", "c", Status.UNKNOWN)]:
        r.add(DomainRecord(name, src, "2021-01-01" if src == "a" else None, "2025-01-01" if src == "b" else None))
        r.domains[name].status = status
        r.domains[name].root = ".".join(name.split(".")[-2:])
    hosts = collapse_to_roots(r)
    assert sorted(r.domains) == ["ex.com", "other.org"]
    ex = r.domains["ex.com"]
    assert ex.status is Status.ACTIVE and ex.sources == {"a", "b"}
    assert (ex.first_seen, ex.last_seen) == ("2021-01-01", "2025-01-01")
    assert hosts == {"ex.com": "www.ex.com", "other.org": "blog.other.org"}   # probe the live member
    assert r.domains["other.org"].status is Status.UNKNOWN


def test_roots_only_scan():
    reg = {"thc": _src("thc", ["a.site.com", "b.site.com", "x.org"])}
    sc = Scanner(ScanOptions(sources=["thc"], roots_only=True, ip_info=False), registry=reg)
    [r] = asyncio.run(sc.run(["8.8.8.8"]))
    assert sorted(r.domains) == ["site.com", "x.org"]


def test_scanned_ips(tmp_path):
    with Store(tmp_path / "db") as st:
        a = st.create_scan(["1.1.1.1", "2.2.2.2"], {})
        st.save_result(a, IPResult("1.1.1.1"))
        b = st.create_scan(["3.3.3.3"], {})
        st.save_result(b, IPResult("3.3.3.3"))
        assert st.scanned_ips() == {"1.1.1.1", "3.3.3.3"}
        assert st.scanned_ips(exclude_scan=b) == {"1.1.1.1"}


# ---------- GUI backend ----------

@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    monkeypatch.setenv("IPSCOPE_NO_KEYRING", "1")
    monkeypatch.setitem(REGISTRY, "modeA", _src("modeA", ["w.site.com", "m.site.com"]))
    monkeypatch.setitem(REGISTRY, "modeB", _src("modeB", fail=True))
    from ipscope.gui.api import Api
    return Api()


def _wait(api):
    end = time.time() + 10
    while api.get_state()["state"] in ("preparing", "running", "stopping") and time.time() < end:
        time.sleep(0.05)
    return api.get_state()


def test_settings_sources_and_preset(api):
    s = api.save_settings({"sources": ["modeA", "nope"], "preset": None, "hide_sources": True})
    assert s["sources"] == ["modeA"] and s["preset"] is None and s["hide_sources"] is True
    assert api.save_settings({"preset": "weird"})["preset"] == "default"
    with pytest.raises(ValueError):
        api.save_settings({"sources": "modeA"})


def test_hide_sources_logs_and_roots_and_skip(api):
    api.save_settings({"hide_sources": True, "roots_only": True, "skip_scanned": True})
    api.start_scan({"targets": "8.8.8.8\n8.8.4.4", "sources": ["modeA", "modeB"], "validate": False})
    st = _wait(api)
    assert st["state"] == "done"
    text = " ".join(l["msg"] for l in st["logs"])
    assert "modeA" not in text and "modeB" not in text and "sources:" not in text
    [scan] = api.list_scans()
    rows = api.results_domains(scan["id"], {})["rows"]
    assert [r["domain"] for r in rows] == ["site.com", "site.com"]         # one root per IP

    api.start_scan({"targets": "8.8.8.8\n1.1.1.1", "sources": ["modeA"], "validate": False})
    st = _wait(api)
    assert st["total"] == 1 and any("already scanned" in l["msg"] for l in st["logs"])


def test_export_without_sources(api, tmp_path):
    import json as _json
    api.save_settings({"hide_sources": True})
    api.start_scan({"targets": "8.8.8.8", "sources": ["modeA", "modeB"], "validate": False})
    _wait(api)
    [scan] = api.list_scans()
    api.export_scan(scan["id"], "csv", path=str(tmp_path / "o.csv"))
    head = (tmp_path / "o.csv").read_text(encoding="utf-8-sig").splitlines()
    assert "sources" not in head[0] and "modeA" not in "".join(head)
    api.export_scan(scan["id"], "json", path=str(tmp_path / "o.json"))
    text = (tmp_path / "o.json").read_text()
    assert "modeA" not in text and "modeB" not in text and _json.loads(text)[0]["domains"]


def test_top_ips(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    from typer.testing import CliRunner
    from ipscope.cli import app
    from ipscope.paths import db_path
    with Store(db_path()) as st:
        sid = st.create_scan(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"], {})
        for ip, n, cat in [("1.1.1.1", 120, "hosting"), ("2.2.2.2", 900, "cdn"), ("3.3.3.3", 60, None), ("4.4.4.4", 3, None)]:
            r = IPResult(ip, info={"category": cat, "provider": "P"})
            for i in range(n):
                r.add(DomainRecord(f"d{i}.x{ip[0]}.com", "s"))
            st.save_result(sid, r)
        assert [r["ip"] for r in st.top_ips(sid, 10, 50)] == ["1.1.1.1", "3.3.3.3"]
        assert st.top_ips(None, 10, 50, exclude_cdn=False)[0]["ip"] == "2.2.2.2"
    res = CliRunner().invoke(app, ["top", "-q", "-o", str(tmp_path / "ips.txt")])
    assert res.exit_code == 0 and res.stdout.split() == ["1.1.1.1", "3.3.3.3"]
    assert (tmp_path / "ips.txt").read_text().split() == ["1.1.1.1", "3.3.3.3"]


def test_local_first_skips_online_on_hit():
    CALLS.clear()
    reg = {"local": _src("local", ["x.com"]), "thc": _src("thc", ["a.com"])}
    sc = Scanner(ScanOptions(sources=["thc", "local"], ip_info=False), registry=reg)
    [r] = asyncio.run(sc.run(["8.8.8.8"]))
    assert CALLS == ["local"] and sorted(r.domains) == ["x.com"]     # index knew it: no online lookup

    CALLS.clear()
    reg = {"local": _src("local"), "thc": _src("thc", ["a.com"])}
    sc = Scanner(ScanOptions(sources=["thc", "local"], ip_info=False), registry=reg)
    [r] = asyncio.run(sc.run(["8.8.8.8"]))
    assert CALLS == ["local", "thc"] and sorted(r.domains) == ["a.com"]   # unknown IP: falls through

    CALLS.clear()
    sc = Scanner(ScanOptions(sources=["thc", "local"], ip_info=False, local_first=False), registry=reg)
    asyncio.run(sc.run(["8.8.8.8"]))
    assert sorted(CALLS) == ["local", "thc"]


def test_results_log_is_append_only(tmp_path):
    from ipscope.results_log import ResultsLog
    f = tmp_path / "results.txt"
    f.write_text("old.com\n", encoding="utf-8")
    a = ResultsLog(True, f)
    a.add(["a.com", "b.com"]); a.add(["a.com", "c.com"]); a.close()
    ResultsLog(True, f).add(["d.com"])
    assert f.read_text(encoding="utf-8").split() == ["old.com", "a.com", "b.com", "c.com", "d.com"]
    off = ResultsLog(False, tmp_path / "x.txt"); off.add(["z.com"])
    assert not (tmp_path / "x.txt").exists()
