"""Your own offline IP -> domain index.

Build it once from domain lists, then reverse lookups are instant, offline and unlimited:

    ipscope index add domains.txt          # plain list, a zone file, or Rapid7 FDNS json(.gz)
    ipscope index resolve                  # resolves every pending name (resumable)
    ipscope scan 1.2.3.4                   # the "local" source now answers from the index

Supported inputs (plain or .gz):
  * one domain per line
  * DNS zone files (e.g. ICANN CZDS): "example.com. 172800 in ns ns1.host.net."
  * Rapid7 Project Sonar FDNS JSON lines: {"name": ..., "type": "a", "value": "1.2.3.4"}
    (already resolved: imported directly, no DNS queries needed)
"""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from ipscope.dns import AsyncResolver
from ipscope.models import normalize_domain
from ipscope.paths import home_dir

PENDING, OK, NXDOMAIN, FAILED = 0, 1, 2, 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS names (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    status      INTEGER NOT NULL DEFAULT 0,   -- 0 pending, 1 resolved, 2 nxdomain/no address, 3 lookup failed
    resolved_at REAL
);
CREATE INDEX IF NOT EXISTS names_status ON names (status, id);
CREATE TABLE IF NOT EXISTS a (
    ip      TEXT NOT NULL,
    name_id INTEGER NOT NULL,
    seen    REAL NOT NULL,
    PRIMARY KEY (ip, name_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS a_name ON a (name_id);
"""


def index_path() -> Path:
    return home_dir() / "index.db"


def _open_text(path: Path) -> io.TextIOBase:
    raw = path.open("rb")
    head = raw.read(2)
    raw.seek(0)
    stream = gzip.GzipFile(fileobj=raw) if head == b"\x1f\x8b" else raw
    return io.TextIOWrapper(stream, encoding="utf-8", errors="ignore")


def detect_format(line: str) -> str:
    s = line.strip()
    if s.startswith("{"):
        return "fdns"
    parts = s.split()
    if len(parts) >= 4 and (parts[2].lower() == "in" or parts[3].lower() in ("ns", "a", "aaaa", "cname", "soa")):
        return "zone"
    return "plain"


def _ip_filter(only: list[str] | None) -> Callable[[str], bool]:
    if not only:
        return lambda ip: True
    import ipaddress

    nets = [ipaddress.ip_network(x.strip(), strict=False) for x in only if x.strip()]
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]

    def keep(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in (v4 if a.version == 4 else v6))

    return keep


class LocalIndex:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else index_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=60, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA temp_store=MEMORY")
        self.db.execute("PRAGMA cache_size=-65536")  # 64 MB page cache
        self.db.executescript(SCHEMA)
        self.db.commit()

    @staticmethod
    def has_data(path: str | Path | None = None) -> bool:
        p = Path(path) if path else index_path()
        if not p.exists() or p.stat().st_size == 0:
            return False
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
            try:
                return con.execute("SELECT 1 FROM a LIMIT 1").fetchone() is not None
            finally:
                con.close()
        except sqlite3.Error:
            return False

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------ import

    def add_names(self, names: Iterable[str], batch: int = 50_000) -> int:
        """Add domains to resolve later. Returns how many were new."""
        before = self.db.total_changes
        buf: list[tuple[str]] = []
        for n in names:
            d = normalize_domain(n)
            if d:
                buf.append((d,))
                if len(buf) >= batch:
                    self.db.executemany("INSERT OR IGNORE INTO names (name) VALUES (?)", buf)
                    self.db.commit()
                    buf.clear()
        if buf:
            self.db.executemany("INSERT OR IGNORE INTO names (name) VALUES (?)", buf)
            self.db.commit()
        return self.db.total_changes - before

    def add_records(self, records: Iterable[tuple[str, str, float]], batch: int = 50_000) -> int:
        """Add already-resolved (name, ip, timestamp) records. Returns rows written."""
        written = 0
        buf: list[tuple[str, str, float]] = []

        def flush():
            nonlocal written
            self.db.executemany(
                "INSERT INTO names (name, status, resolved_at) VALUES (?, 1, ?) "
                "ON CONFLICT(name) DO UPDATE SET status=1, resolved_at=MAX(COALESCE(resolved_at, 0), excluded.resolved_at)",
                [(n, ts) for n, _, ts in buf],
            )
            self.db.executemany(
                "INSERT OR REPLACE INTO a (ip, name_id, seen) SELECT ?, id, ? FROM names WHERE name=?",
                [(ip, ts, n) for n, ip, ts in buf],
            )
            self.db.commit()
            written += len(buf)
            buf.clear()

        for name, ip, ts in records:
            d = normalize_domain(name)
            if d and ip:
                buf.append((d, ip.strip(), ts))
                if len(buf) >= batch:
                    flush()
        if buf:
            flush()
        return written

    def import_file(self, path: str | Path, on_progress: Callable[[int], None] | None = None,
                    should_stop: Callable[[], bool] | None = None, only: list[str] | None = None) -> dict:
        """Import a list / zone file / FDNS dump. Returns {"format", "lines", "names", "records"}.

        only: CIDR ranges / IPs - for FDNS dumps, keep just records pointing into them
        (turns a multi-billion-record dump into a small index for your targets).
        """
        path = Path(path)
        keep_ip = _ip_filter(only)
        with _open_text(path) as f:
            first = ""
            for first in f:
                if first.strip() and not first.lstrip().startswith((";", "#", "$")):
                    break
            fmt = detect_format(first)
            counter = {"lines": 0}

            def lines() -> Iterator[str]:
                yield first
                for line in f:
                    counter["lines"] += 1
                    if counter["lines"] % 200_000 == 0:
                        if on_progress:
                            on_progress(counter["lines"])
                        if should_stop and should_stop():
                            return
                    yield line

            if fmt == "fdns":
                def recs():
                    for line in lines():
                        try:
                            o = json.loads(line)
                        except ValueError:
                            continue
                        if str(o.get("type", "")).lower() in ("a", "aaaa") and keep_ip(str(o.get("value", ""))):
                            try:
                                ts = float(o.get("timestamp") or time.time())
                            except (TypeError, ValueError):
                                ts = time.time()
                            yield o.get("name", ""), str(o.get("value", "")), ts
                return {"format": fmt, "names": 0, "records": self.add_records(recs()), "lines": counter["lines"] + 1}

            if fmt == "zone":
                def zone_names():
                    for line in lines():
                        if line[:1] in (";", "$", " ", "\t") or not line.strip():
                            continue
                        yield line.split(None, 1)[0].rstrip(".")
                return {"format": fmt, "names": self.add_names(zone_names()), "records": 0, "lines": counter["lines"] + 1}

            def plain():
                for line in lines():
                    s = line.strip()
                    if s and not s.startswith("#"):
                        yield s.split(",")[0].split()[0]
            return {"format": fmt, "names": self.add_names(plain()), "records": 0, "lines": counter["lines"] + 1}

    # ------------------------------------------------------------ resolve

    def pending_count(self, retry_failed: bool = False, refresh_days: float | None = None) -> int:
        where, args = self._pending_where(retry_failed, refresh_days)
        return self.db.execute(f"SELECT COUNT(*) FROM names WHERE {where}", args).fetchone()[0]

    @staticmethod
    def _pending_where(retry_failed: bool, refresh_days: float | None):
        conds, args = ["status = 0"], []
        if retry_failed:
            conds.append("status = 3")
        if refresh_days is not None:
            conds.append("(status IN (1, 2) AND resolved_at < ?)")
            args.append(time.time() - refresh_days * 86400)
        return "(" + " OR ".join(conds) + ")", args

    async def resolve(
        self,
        concurrency: int = 500,
        retry_failed: bool = False,
        refresh_days: float | None = None,
        limit: int | None = None,
        on_progress: Callable[[dict], None] | None = None,
        resolver: AsyncResolver | None = None,
        chunk: int = 5000,
    ) -> dict:
        """Resolve pending names; safe to interrupt and run again."""
        resolver = resolver or AsyncResolver(timeout=5, concurrency=concurrency, cache_size=0)
        where, args = self._pending_where(retry_failed, refresh_days)
        stats = {"done": 0, "ok": 0, "nx": 0, "failed": 0, "records": 0}
        last_id = 0
        while limit is None or stats["done"] < limit:
            take = chunk if limit is None else min(chunk, limit - stats["done"])
            rows = self.db.execute(
                f"SELECT id, name FROM names WHERE {where} AND id > ? ORDER BY id LIMIT ?",
                [*args, last_id, take],
            ).fetchall()
            if not rows:
                break
            last_id = rows[-1][0]
            answers = await asyncio.gather(*(resolver.resolve(name) for _, name in rows))
            now = time.time()
            updates, a_rows = [], []
            for (nid, _), res in zip(rows, answers):
                if res is None:
                    updates.append((FAILED, now, nid))
                    stats["failed"] += 1
                elif not res:
                    updates.append((NXDOMAIN, now, nid))
                    stats["nx"] += 1
                else:
                    updates.append((OK, now, nid))
                    stats["ok"] += 1
                    a_rows += [(ip, nid, now) for ip in res]
            ids = [(nid,) for nid, _ in rows]
            self.db.executemany("DELETE FROM a WHERE name_id=?", ids)
            self.db.executemany("INSERT OR REPLACE INTO a (ip, name_id, seen) VALUES (?,?,?)", a_rows)
            self.db.executemany("UPDATE names SET status=?, resolved_at=? WHERE id=?", updates)
            self.db.commit()
            stats["done"] += len(rows)
            stats["records"] += len(a_rows)
            if on_progress:
                on_progress(dict(stats))
        return stats

    # ------------------------------------------------------------ query

    def lookup(self, ip: str) -> list[tuple[str, float]]:
        return [
            (r[0], r[1]) for r in self.db.execute(
                "SELECT n.name, a.seen FROM a JOIN names n ON n.id = a.name_id WHERE a.ip=? ORDER BY n.name",
                (ip,),
            )
        ]

    def top_ips(self, limit: int = 100, min_domains: int = 1) -> list[tuple[str, int]]:
        """IPs with the most domains in the index."""
        return [
            (r[0], r[1]) for r in self.db.execute(
                "SELECT ip, COUNT(*) c FROM a GROUP BY ip HAVING c >= ? ORDER BY c DESC, ip LIMIT ?",
                (min_domains, limit),
            )
        ]

    def stats(self) -> dict:
        counts = dict(self.db.execute("SELECT status, COUNT(*) FROM names GROUP BY status").fetchall())
        records = self.db.execute("SELECT COUNT(*) FROM a").fetchone()[0]
        size = sum(p.stat().st_size for p in (self.path, Path(str(self.path) + "-wal")) if p.exists())
        last = self.db.execute("SELECT MAX(resolved_at) FROM names").fetchone()[0]
        return {
            "names": sum(counts.values()),
            "resolved": counts.get(OK, 0),
            "nxdomain": counts.get(NXDOMAIN, 0),
            "failed": counts.get(FAILED, 0),
            "pending": counts.get(PENDING, 0),
            "records": records,
            "size_bytes": size,
            "last_resolved": last,
            "path": str(self.path),
        }
