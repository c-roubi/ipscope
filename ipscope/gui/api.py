"""Backend exposed to the web UI as window.pywebview.api.

Every public method is callable from JavaScript and must return JSON-serialisable data.
Scans run in a background thread with their own asyncio loop; the UI polls get_state().
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from pathlib import Path

from ipscope import __version__
from ipscope.results_log import ResultsLog
from ipscope.engine import AllSourcesDisabled, ScanOptions, Scanner
from ipscope.export import export_scan
from ipscope.inputs import expand_targets
from ipscope.keys import KeyStore, mask
from ipscope.models import IPResult, Status
from ipscope.paths import db_path, home_dir
from ipscope.index import LocalIndex
from ipscope.sources import ACTIVE_SOURCES, PRESETS, REGISTRY, default_sources, preset_sources
from ipscope.storage import Store

DEFAULT_SETTINGS = {
    "concurrency": 10,
    "timeout": 15,
    "cache_ttl_hours": 24,
    "probe_limit": 200,
    "max_hosts": 65536,
    "validate": True,
    "probe": False,
    "active": False,
    "allow_private": False,
    "use_cache": True,
    "roots_only": False,      # store root domains only
    "local_first": True,      # answer from the local index first, skip online sources on a hit
    "first_hit": False,       # stop at the first source that finds domains
    "skip_scanned": False,    # skip IPs finished in earlier scans
    "save_results_txt": True,  # append every domain found to ~/.ipscope/results.txt (never cleared)
    "hide_sources": False,    # never show source names (screen recording)
}
# non-scalar settings
LIST_SETTINGS = {"sources": None, "preset": "default"}


class _Job:
    def __init__(self):
        self.state = "idle"          # idle | preparing | running | stopping | done | paused | error
        self.scan_id: int | None = None
        self.total = 0
        self.done = 0
        self.found = 0
        self.active = 0
        self.errors = 0
        self.started = 0.0
        self.loop: asyncio.AbstractEventLoop | None = None
        self.task: asyncio.Task | None = None
        self.thread: threading.Thread | None = None


class Api:
    def __init__(self):
        self._window = None
        self._job = _Job()
        self._lock = threading.Lock()
        self._logs: deque = deque(maxlen=2000)
        self._seq = 0
        self._ix = {"state": "idle", "phase": "", "done": 0, "total": 0, "ok": 0, "lines": 0,
                    "stop": threading.Event(), "loop": None, "task": None}
        self._ix_logs: deque = deque(maxlen=1000)
        self._ix_seq = 0

    # ------------------------------------------------------------ helpers

    def _log(self, msg: str, level: str = "info") -> None:
        with self._lock:
            self._seq += 1
            self._logs.append({"seq": self._seq, "t": time.strftime("%H:%M:%S"), "level": level, "msg": msg})

    def _settings_path(self) -> Path:
        return home_dir() / "settings.json"

    def _dialog(self, kind: str, **kw):
        if self._window is None:
            return None
        import webview  # only available in the desktop app
        fd = getattr(webview, "FileDialog", None)
        const = getattr(fd, kind) if fd else getattr(webview, f"{kind}_DIALOG")
        return self._window.create_file_dialog(const, **kw)

    # ------------------------------------------------------------ meta / settings

    def get_meta(self) -> dict:
        keys = KeyStore().resolve_all(REGISTRY)
        defaults = default_sources(keys)
        sources = [
            {
                "name": name,
                "description": cls.description,
                "active": cls.active,
                "requires_key": cls.requires_key,
                "uses_key": bool(cls.key_env),
                "has_key": bool(keys.get(name)),
                "default": name in defaults,
                "needs_index": name == "local" and name not in defaults,
            }
            for name, cls in REGISTRY.items()
        ]
        presets = {}
        for pname, pdef in PRESETS.items():
            srcs, act = preset_sources(pname, keys)
            presets[pname] = {"sources": srcs, "active": act, "help": pdef["help"]}
        return {
            "presets": presets,
            "version": __version__,
            "home": str(home_dir()),
            "db": str(db_path()),
            "keyring": KeyStore().backend,
            "sources": sources,
        }

    def get_settings(self) -> dict:
        data = {**DEFAULT_SETTINGS, **LIST_SETTINGS}
        try:
            data.update(json.loads(self._settings_path().read_text(encoding="utf-8")))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return data

    def save_settings(self, values: dict) -> dict:
        data = self.get_settings()
        for k, default in DEFAULT_SETTINGS.items():
            if k not in values:
                continue
            v = values[k]
            try:
                data[k] = bool(v) if isinstance(default, bool) else type(default)(v)
            except (TypeError, ValueError):
                raise ValueError(f"invalid value for {k}")
        if "sources" in values:
            src = values["sources"]
            if src is not None and (not isinstance(src, list) or not all(isinstance(x, str) for x in src)):
                raise ValueError("invalid value for sources")
            data["sources"] = [x for x in src if x in REGISTRY] if src is not None else None
        if "preset" in values:
            pv = values["preset"]
            data["preset"] = pv if pv in (None, "default", *PRESETS) else "default"
        data["concurrency"] = max(1, min(500, data["concurrency"]))
        data["timeout"] = max(1, data["timeout"])
        data["probe_limit"] = max(1, data["probe_limit"])
        data["max_hosts"] = max(1, data["max_hosts"])
        data["cache_ttl_hours"] = max(0, data["cache_ttl_hours"])
        self._settings_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

    # ------------------------------------------------------------ scanning

    def pick_targets_file(self):
        paths = self._dialog("OPEN", file_types=("Target lists (*.txt;*.csv)", "All files (*.*)"))
        if not paths:
            return None
        path = paths[0] if isinstance(paths, (list, tuple)) else paths
        return Path(path).read_text(encoding="utf-8", errors="ignore")

    def _options(self, params: dict) -> ScanOptions:
        s = self.get_settings()
        sources = [x for x in (params.get("sources") or []) if x in REGISTRY]
        if not sources:
            raise ValueError("Select at least one source")
        if params.get("active", s["active"]):
            sources += [x for x in ACTIVE_SOURCES if x not in sources]
        return ScanOptions(
            sources=sources,
            concurrency=int(s["concurrency"]),
            validate=bool(params.get("validate", s["validate"])),
            timeout=float(s["timeout"]),
            use_cache=bool(params.get("use_cache", s["use_cache"])),
            cache_ttl=float(s["cache_ttl_hours"]) * 3600,
            probe=bool(params.get("probe", s["probe"])),
            probe_limit=int(s["probe_limit"]),
            roots_only=bool(s["roots_only"]),
            local_first=bool(s["local_first"]),
            first_hit=bool(s["first_hit"]),
        )

    def _busy(self) -> bool:
        return self._job.state in ("preparing", "running", "stopping")

    def start_scan(self, params: dict) -> dict:
        if self._busy():
            raise RuntimeError("A scan is already running")
        items = [x for x in str(params.get("targets") or "").splitlines() if x.strip()]
        if not items:
            raise ValueError("Add at least one target")
        opts = self._options(params)
        s = self.get_settings()
        self._start_thread(dict(
            items=items, opts=opts, label=(params.get("label") or "").strip() or None,
            allow_private=bool(params.get("allow_private", s["allow_private"])),
            max_hosts=int(s["max_hosts"]),
        ))
        return {"ok": True}

    def resume_scan(self, scan_id: int) -> dict:
        if self._busy():
            raise RuntimeError("A scan is already running")
        with Store(db_path()) as st:
            info = st.get_scan(int(scan_id))
        if not info:
            raise ValueError(f"Scan #{scan_id} not found")
        if info["done"] >= info["total"]:
            raise ValueError(f"Scan #{scan_id} is already complete")
        self._start_thread(dict(resume_id=int(scan_id), opts=ScanOptions.from_dict(info["options"])))
        return {"ok": True}

    def stop_scan(self) -> dict:
        job = self._job
        if job.state in ("preparing", "running") and job.loop and job.task:
            job.state = "stopping"
            self._log("Stopping... progress so far is saved", "warn")
            job.loop.call_soon_threadsafe(job.task.cancel)
        return {"ok": True}

    def _start_thread(self, kw: dict) -> None:
        job = _Job()
        job.state = "preparing"
        job.started = time.time()
        self._job = job
        job.thread = threading.Thread(target=lambda: asyncio.run(self._run(job, **kw)), daemon=True)
        job.thread.start()

    async def _run(self, job: _Job, opts: ScanOptions, items=None, label=None,
                   allow_private=False, max_hosts=65536, resume_id=None) -> None:
        job.loop = asyncio.get_running_loop()
        job.task = asyncio.current_task()
        settings = self.get_settings()
        hide = bool(settings["hide_sources"])
        rlog = ResultsLog(bool(settings["save_results_txt"]))
        store = Store(db_path())
        try:
            if resume_id:
                job.scan_id = resume_id
                ips = store.pending_ips(resume_id)
                info = store.get_scan(resume_id)
                job.total, job.done = info["total"], info["done"]
                for r in store.results(resume_id):
                    job.found += len(r.domains)
                    job.active += r.count(Status.ACTIVE)
                store.set_status(resume_id, "running")
                self._log(f"Resuming scan #{resume_id}: {job.done}/{job.total} done")
            else:
                self._log(f"Expanding {len(items)} target line(s)...")
                ips, warnings = await expand_targets(items, allow_private=allow_private, max_hosts=max_hosts)
                for w in warnings:
                    self._log(w, "warn")
                if ips and settings["skip_scanned"]:
                    seen = store.scanned_ips()
                    before = len(ips)
                    ips = [ip for ip in ips if ip not in seen]
                    if before - len(ips):
                        self._log(f"Skipped {before - len(ips):,} IP(s) already scanned before", "warn")
                if not ips:
                    self._log("Nothing to scan", "error")
                    job.state = "error"
                    return
                job.scan_id = store.create_scan(ips, opts.to_dict(), label)
                job.total = len(ips)
                if hide:
                    self._log(f"Scan #{job.scan_id}: {len(ips):,} IP(s)")
                else:
                    self._log(f"Scan #{job.scan_id}: {len(ips):,} IP(s), sources: {', '.join(opts.sources)}")

            def on_result(r: IPResult):
                store.save_result(job.scan_id, r)
                rlog.add(r.domains)
                job.done += 1
                job.found += len(r.domains)
                job.active += r.count(Status.ACTIVE)
                job.errors += len(r.errors)
                # The log stays plain: IP + count. Provider / CDN names live in the Results page.
                self._log(f"{r.ip}  {len(r.domains)} new domain(s)", "ok" if r.domains else "info")
                if hide:
                    if r.errors and not r.domains:
                        self._log(f"{r.ip}  {len(r.errors)} lookup(s) failed", "error")
                else:
                    for src, err in r.errors.items():
                        self._log(f"{r.ip}  {src}: {err}", "error")

            def on_event(level, msg):
                self._log("A data source was paused for the rest of this scan (limit reached)" if hide else msg, level)

            scanner = Scanner(opts, on_result=on_result, keys=KeyStore().resolve_all(REGISTRY), store=store,
                              on_event=on_event)
            job.state = "running"
            try:
                await scanner.run(ips, collect=False)
            finally:
                if scanner.stats.skipped_sources and not hide:
                    self._log(f"Skipped (not set up): {', '.join(scanner.stats.skipped_sources)}", "warn")
            store.set_status(job.scan_id, "done")
            job.state = "done"
            st = scanner.stats
            self._log(f"Done in {time.time() - job.started:.1f}s - {job.found} domains, "
                      f"{st.requests} requests, {st.cache_hits} cache hits", "ok")
        except AllSourcesDisabled as e:
            store.set_status(job.scan_id, "interrupted")
            job.state = "paused"
            self._log("Stopped: every data source reached its limit. Resume it later from History." if hide
                      else f"Stopped: {e}. Fix the source (key/quota) and resume it from History.", "error")
        except asyncio.CancelledError:
            if job.scan_id:
                store.set_status(job.scan_id, "interrupted")
            job.state = "paused"
            self._log(f"Paused at {job.done}/{job.total}. Resume it from History.", "warn")
        except Exception as e:  # noqa: BLE001 - surface every failure in the log
            if job.scan_id:
                store.set_status(job.scan_id, "interrupted")
            job.state = "error"
            self._log(f"Error: {e}", "error")
        finally:
            rlog.close()
            store.close()

    def get_state(self, cursor: int = 0) -> dict:
        job = self._job
        with self._lock:
            logs = [entry for entry in self._logs if entry["seq"] > int(cursor or 0)]
        return {
            "state": job.state,
            "scan_id": job.scan_id,
            "total": job.total,
            "done": job.done,
            "found": job.found,
            "active": job.active,
            "errors": job.errors,
            "elapsed": round(time.time() - job.started, 1) if job.started else 0,
            "logs": logs,
            "cursor": logs[-1]["seq"] if logs else int(cursor or 0),
        }

    def clear_logs(self) -> dict:
        with self._lock:
            self._logs.clear()
        return {"ok": True}

    # ------------------------------------------------------------ history / results

    def list_scans(self, limit: int = 200) -> list[dict]:
        with Store(db_path()) as st:
            rows = st.list_scans(int(limit))
        for r in rows:
            r["date"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created_at"]))
        return rows

    def results_summary(self, scan_id: int) -> dict:
        with Store(db_path()) as st:
            info = st.get_scan(int(scan_id))
            if not info:
                raise ValueError(f"Scan #{scan_id} not found")
            summary = st.summary(int(scan_id))
        info["date"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(info["created_at"]))
        return {"scan": info, "summary": summary}

    def results_ips(self, scan_id: int, search: str = "", offset: int = 0, limit: int = 200) -> dict:
        with Store(db_path()) as st:
            rows, total = st.list_ips(int(scan_id), search=search, offset=int(offset), limit=min(int(limit), 1000))
        return {"rows": rows, "total": total}

    def results_domains(self, scan_id: int, filters: dict, offset: int = 0, limit: int = 200) -> dict:
        f = filters or {}
        ip, status, search = f.get("ip") or None, f.get("status") or "all", f.get("search") or ""
        limit = min(int(limit), 1000)
        with Store(db_path()) as st:
            if f.get("roots"):
                rows, total = st.query_roots(int(scan_id), ip, status, search, int(offset), limit)
            else:
                rows, total = st.query_domains(int(scan_id), ip, status, search, int(offset), limit)
            counts = st.status_counts(int(scan_id), ip, search)
        return {"rows": rows, "total": total, "counts": counts}

    def results_copy(self, scan_id: int, filters: dict, limit: int = 500_000) -> dict:
        f = filters or {}
        with Store(db_path()) as st:
            names = st.domain_names(int(scan_id), f.get("ip") or None, f.get("status") or "all",
                                    f.get("search") or "", bool(f.get("roots")), int(limit) + 1)
        truncated = len(names) > int(limit)
        return {"text": "\n".join(names[: int(limit)]), "count": min(len(names), int(limit)), "truncated": truncated}

    def delete_scan(self, scan_id: int) -> dict:
        if self._busy() and self._job.scan_id == int(scan_id):
            raise RuntimeError("Stop the scan before deleting it")
        with Store(db_path()) as st:
            ok = st.delete_scan(int(scan_id))
        return {"ok": ok}

    def export_scan(self, scan_id: int, fmt: str = "csv", only_active: bool = False,
                    roots: bool = False, path: str | None = None) -> dict:
        fmt = fmt if fmt in ("csv", "json", "txt") else "csv"
        if path is None:
            chosen = self._dialog("SAVE", save_filename=f"ipscope-scan-{scan_id}.{fmt}")
            if not chosen:
                return {"ok": False, "cancelled": True}
            path = chosen[0] if isinstance(chosen, (list, tuple)) else chosen
        p = Path(path)
        if p.suffix.lower() != f".{fmt}":
            p = p.with_suffix(f".{fmt}")
        with Store(db_path()) as st:
            n = export_scan(st, int(scan_id), p, only_active=bool(only_active), roots_only=bool(roots),
                            include_sources=not self.get_settings()["hide_sources"])
        return {"ok": True, "path": str(p), "rows": n}

    # ------------------------------------------------------------ keys

    def keys_list(self) -> dict:
        ks = KeyStore()
        items = []
        for name, cls in REGISTRY.items():
            if not cls.key_env:
                continue
            keys, where = ks.resolve(name, cls.key_env)
            items.append({
                "name": name, "description": cls.description, "requires_key": cls.requires_key,
                "env": cls.key_env, "from": where, "keys": [mask(k) for k in keys],
            })
        return {"backend": ks.backend, "items": items}

    def keys_set(self, name: str, key: str, add: bool = False) -> dict:
        cls = REGISTRY.get(name)
        if not cls or not cls.key_env:
            raise ValueError(f"{name} does not use an API key")
        key = (key or "").strip()
        if not key:
            raise ValueError("Key is empty")
        ks = KeyStore()
        if add:
            ks.add(name, key)
        else:
            ks.set(name, [key])
        return {"ok": True, "count": len(ks.get(name))}

    def keys_delete(self, name: str) -> dict:
        return {"ok": KeyStore().delete(name)}

    # ------------------------------------------------------------ local index

    def _ix_log(self, msg: str, level: str = "info") -> None:
        with self._lock:
            self._ix_seq += 1
            self._ix_logs.append({"seq": self._ix_seq, "t": time.strftime("%H:%M:%S"), "level": level, "msg": msg})

    def index_stats(self) -> dict:
        with LocalIndex() as idx:
            return idx.stats()

    def index_state(self, cursor: int = 0) -> dict:
        ix = self._ix
        with self._lock:
            logs = [e for e in self._ix_logs if e["seq"] > int(cursor or 0)]
        return {
            "state": ix["state"], "phase": ix["phase"], "done": ix["done"], "total": ix["total"],
            "ok": ix["ok"], "lines": ix["lines"], "logs": logs,
            "cursor": logs[-1]["seq"] if logs else int(cursor or 0),
        }

    def index_import(self, paths: list | None = None, concurrency: int = 500) -> dict:
        if self._ix["state"] == "running":
            raise RuntimeError("The index is already busy")
        if paths is None:
            chosen = self._dialog("OPEN", allow_multiple=True,
                                  file_types=("Domain lists (*.txt;*.csv;*.gz;*.json;*.zone)", "All files (*.*)"))
            if not chosen:
                return {"ok": False, "cancelled": True}
            paths = list(chosen) if isinstance(chosen, (list, tuple)) else [chosen]
        self._ix_start(paths=[str(x) for x in paths], concurrency=int(concurrency))
        return {"ok": True}

    def index_resolve(self, retry_failed: bool = False, concurrency: int = 500) -> dict:
        if self._ix["state"] == "running":
            raise RuntimeError("The index is already busy")
        self._ix_start(paths=[], concurrency=int(concurrency), retry_failed=bool(retry_failed))
        return {"ok": True}

    def index_stop(self) -> dict:
        ix = self._ix
        if ix["state"] == "running":
            ix["stop"].set()          # import checks this flag between batches
            if ix["phase"] == "resolve" and ix["loop"] and ix["task"]:
                ix["loop"].call_soon_threadsafe(ix["task"].cancel)
            self._ix_log("Stopping... everything done so far is saved", "warn")
        return {"ok": True}

    def _ix_start(self, **kw) -> None:
        ix = self._ix
        ix.update(state="running", phase="", done=0, total=0, ok=0, lines=0, loop=None, task=None)
        ix["stop"] = threading.Event()
        threading.Thread(target=lambda: asyncio.run(self._ix_run(**kw)), daemon=True).start()

    async def _ix_run(self, paths: list[str], concurrency: int, retry_failed: bool = False) -> None:
        ix = self._ix
        ix["loop"], ix["task"] = asyncio.get_running_loop(), asyncio.current_task()
        idx = LocalIndex()
        try:
            for path in paths:
                ix["phase"], ix["lines"] = "import", 0
                self._ix_log(f"Importing {Path(path).name}...")

                def prog(n):
                    ix["lines"] = n

                res = await asyncio.to_thread(idx.import_file, path, prog, ix["stop"].is_set)
                what = (f"{res['records']:,} resolved records" if res["format"] == "fdns"
                        else f"{res['names']:,} new names")
                self._ix_log(f"{Path(path).name}: {res['format']} file, {res['lines']:,} lines -> {what}", "ok")
                if ix["stop"].is_set():
                    raise asyncio.CancelledError
            ix["phase"] = "resolve"
            ix["total"] = idx.pending_count(retry_failed)
            if not ix["total"]:
                self._ix_log("Nothing to resolve", "info")
            else:
                self._ix_log(f"Resolving {ix['total']:,} names, {concurrency} at a time...")

                def rprog(st):
                    ix["done"], ix["ok"] = st["done"], st["ok"]

                st = await idx.resolve(concurrency=concurrency, retry_failed=retry_failed, on_progress=rprog)
                self._ix_log(f"Done: {st['ok']:,} resolved ({st['records']:,} IP records), {st['nx']:,} without "
                             f"address, {st['failed']:,} failed", "ok")
            ix["state"] = "done"
        except asyncio.CancelledError:
            ix["state"] = "paused"
            self._ix_log("Paused. Click Resolve pending to continue.", "warn")
        except Exception as e:  # noqa: BLE001
            ix["state"] = "error"
            self._ix_log(f"Error: {e}", "error")
        finally:
            idx.close()

    # ------------------------------------------------------------ cache / system

    def cache_stats(self) -> list[dict]:
        with Store(db_path()) as st:
            return [{"source": s, "count": n} for s, n in st.cache_stats()]

    def cache_clear(self) -> dict:
        with Store(db_path()) as st:
            return {"removed": st.cache_clear()}

    def open_url(self, url: str) -> dict:
        if not str(url).startswith(("http://", "https://")):
            url = "http://" + str(url)
        webbrowser.open(url)
        return {"ok": True}

    def open_folder(self) -> dict:
        path = str(home_dir())
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return {"ok": True}
