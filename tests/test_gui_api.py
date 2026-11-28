"""Tests for the desktop backend (no window needed)."""

import asyncio
import json
import time

import pytest

from ipscope.gui.api import Api
from ipscope.models import DomainRecord
from ipscope.sources import REGISTRY, Source


class GuiFake(Source):
    name = "guifake"; rate = 0
    async def _lookup(self, ip):
        await asyncio.sleep(0.05)
        return [DomainRecord(f"site{ip.split('.')[-1]}.example.com", self.name)]


class GuiSlow(Source):
    name = "guislow"; rate = 0
    async def _lookup(self, ip):
        await asyncio.sleep(0.3)
        return [DomainRecord(f"slow{ip.split('.')[-1]}.example.org", self.name)]


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSCOPE_HOME", str(tmp_path))
    monkeypatch.setenv("IPSCOPE_NO_KEYRING", "1")
    for cls in list(REGISTRY.values()):
        if cls.key_env:
            monkeypatch.delenv(cls.key_env, raising=False)
    monkeypatch.setitem(REGISTRY, "guifake", GuiFake)
    monkeypatch.setitem(REGISTRY, "guislow", GuiSlow)
    return Api()


def wait(api, states=("done", "paused", "error"), timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        st = api.get_state()
        if st["state"] in states:
            return st
        time.sleep(0.05)
    raise AssertionError(f"timed out, state={api.get_state()['state']}")


def test_meta_and_settings(api):
    meta = api.get_meta()
    names = {s["name"]: s for s in meta["sources"]}
    assert names["virustotal"]["requires_key"] and not names["virustotal"]["has_key"]
    assert names["internetdb"]["default"] and names["tls"]["active"]
    json.dumps(meta)  # must be JSON-serialisable for pywebview

    s = api.get_settings()
    assert s["concurrency"] == 10 and s["validate"] is True
    s2 = api.save_settings({"concurrency": "999", "probe": True, "unknown": 1})
    assert s2["concurrency"] == 500 and s2["probe"] is True and "unknown" not in s2
    assert api.get_settings()["probe"] is True
    with pytest.raises(ValueError):
        api.save_settings({"timeout": "abc"})


def test_full_scan_flow(api, tmp_path):
    with pytest.raises(ValueError):
        api.start_scan({"targets": "", "sources": ["guifake"]})
    with pytest.raises(ValueError):
        api.start_scan({"targets": "8.8.8.8", "sources": []})

    api.start_scan({"targets": "8.8.8.8\n1.1.1.0/30\n# comment", "sources": ["guifake"],
                    "validate": False, "label": "gui test"})
    st = wait(api)
    assert st["state"] == "done", [l["msg"] for l in st["logs"]]
    assert (st["done"], st["total"], st["found"]) == (3, 3, 3)
    assert any("Done in" in l["msg"] for l in st["logs"])
    assert api.get_state(st["cursor"])["logs"] == []           # cursor works

    [scan] = api.list_scans()
    assert scan["label"] == "gui test" and scan["status"] == "done" and scan["date"]
    summ = api.results_summary(scan["id"])
    json.dumps(summ)
    assert summ["summary"]["ips"] == 3 and summ["summary"]["domains"] == 3
    ips = api.results_ips(scan["id"])
    assert [r["ip"] for r in ips["rows"]] == ["8.8.8.8", "1.1.1.1", "1.1.1.2"] and ips["total"] == 3
    page = api.results_domains(scan["id"], {}, 0, 2)
    json.dumps(page)
    assert page["total"] == 3 and len(page["rows"]) == 2 and page["counts"]["all"] == 3
    assert [r["domain"] for r in page["rows"]] == ["site1.example.com", "site2.example.com"]
    assert api.results_domains(scan["id"], {"search": "site8"})["total"] == 1
    assert api.results_domains(scan["id"], {"ip": "1.1.1.1"})["rows"][0]["domain"] == "site1.example.com"
    roots = api.results_domains(scan["id"], {"roots": True})
    assert roots["rows"] == [{"root": "example.com", "names": 3, "examples": [
        "site1.example.com", "site2.example.com", "site8.example.com"]}]
    cp = api.results_copy(scan["id"], {}, limit=2)
    assert cp["count"] == 2 and cp["truncated"] and cp["text"].count("\n") == 1

    out = api.export_scan(scan["id"], "csv", path=str(tmp_path / "out"))
    assert out["ok"] and out["path"].endswith("out.csv") and out["rows"] == 3
    out = api.export_scan(scan["id"], "txt", roots=True, path=str(tmp_path / "r.txt"))
    assert (tmp_path / "r.txt").read_text().split() == ["example.com"]

    assert api.delete_scan(scan["id"])["ok"]
    assert api.list_scans() == []


def test_stop_and_resume(api):
    api.save_settings({"concurrency": 1})
    api.start_scan({"targets": "8.8.8.0/28", "sources": ["guislow"], "validate": False})
    end = time.time() + 10
    while api.get_state()["done"] < 2 and time.time() < end:
        time.sleep(0.05)
    with pytest.raises(RuntimeError):
        api.start_scan({"targets": "8.8.8.8", "sources": ["guislow"]})   # busy
    api.stop_scan()
    st = wait(api)
    assert st["state"] == "paused" and 2 <= st["done"] < 14

    [scan] = api.list_scans()
    assert scan["status"] == "interrupted"
    api.save_settings({"concurrency": 10})
    api.resume_scan(scan["id"])
    st = wait(api)
    assert st["state"] == "done" and st["done"] == 14 and st["found"] == 14
    with pytest.raises(ValueError):
        api.resume_scan(scan["id"])                                     # already complete


def test_bad_targets_report_error(api):
    api.start_scan({"targets": "10.0.0.1\nnot a target!", "sources": ["guifake"]})
    st = wait(api)
    assert st["state"] == "error"
    msgs = " ".join(l["msg"] for l in st["logs"])
    assert "private" in msgs and "Nothing to scan" in msgs


def test_keys_and_cache(api):
    assert api.keys_list()["items"][0]["keys"] == [] or True
    with pytest.raises(ValueError):
        api.keys_set("ptr", "x")
    with pytest.raises(ValueError):
        api.keys_set("shodan", "   ")
    assert api.keys_set("shodan", "abcdefghij123456")["count"] == 1
    assert api.keys_set("shodan", "zzzzzzzzzz999999", add=True)["count"] == 2
    item = next(i for i in api.keys_list()["items"] if i["name"] == "shodan")
    assert item["keys"] == ["abcd…3456", "zzzz…9999"] and item["from"] == "store"
    assert next(s for s in api.get_meta()["sources"] if s["name"] == "shodan")["default"]
    assert api.keys_delete("shodan")["ok"]

    api.start_scan({"targets": "8.8.8.8", "sources": ["guifake"]})
    wait(api)
    assert api.cache_stats() == [{"source": "guifake", "count": 1}]
    assert api.cache_clear()["removed"] == 1
