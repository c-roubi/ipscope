"""SQLite storage: per-source result cache, scan history (pause/resume) and
per-domain result rows that can be paged, filtered and streamed without
loading a whole scan into memory."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path

from ipscope.models import DomainRecord, IPResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    source     TEXT NOT NULL,
    ip         TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    records    TEXT NOT NULL,
    PRIMARY KEY (source, ip)
);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  REAL NOT NULL,
    finished_at REAL,
    status      TEXT NOT NULL,          -- running | interrupted | done
    label       TEXT,
    options     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_ips (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    pos     INTEGER NOT NULL,
    ip      TEXT NOT NULL,
    done    INTEGER NOT NULL DEFAULT 0,
    result  TEXT,                       -- {"ip", "errors", "info"} (domains live in scan_domains)
    PRIMARY KEY (scan_id, ip)
);
CREATE INDEX IF NOT EXISTS scan_ips_pending ON scan_ips (scan_id, done);
CREATE TABLE IF NOT EXISTS scan_domains (
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip         TEXT NOT NULL,
    domain     TEXT NOT NULL,
    root       TEXT,
    status     TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 0,
    title      TEXT,
    tech       TEXT,
    data       TEXT NOT NULL,           -- full JSON of the domain entry
    PRIMARY KEY (scan_id, ip, domain)
);
CREATE INDEX IF NOT EXISTS scan_domains_status ON scan_domains (scan_id, status);
CREATE INDEX IF NOT EXISTS scan_domains_root ON scan_domains (scan_id, root);
CREATE INDEX IF NOT EXISTS scan_domains_domain ON scan_domains (scan_id, domain);
"""

# columns added to scan_ips after v0.4 (migrated in place)
_IP_COLUMNS = {
    "v2": "INTEGER NOT NULL DEFAULT 0",   # 1 = domains stored in scan_domains
    "n_domains": "INTEGER NOT NULL DEFAULT 0",
    "n_active": "INTEGER NOT NULL DEFAULT 0",
    "n_errors": "INTEGER NOT NULL DEFAULT 0",
    "asn": "INTEGER",
    "provider": "TEXT",
    "category": "TEXT",
    "hosting": "TEXT",
}


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, much faster commits
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        have = {r["name"] for r in self.db.execute("PRAGMA table_info(scan_ips)")}
        for col, ddl in _IP_COLUMNS.items():
            if col not in have:
                self.db.execute(f"ALTER TABLE scan_ips ADD COLUMN {col} {ddl}")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ================================================================ cache

    def cache_get(self, source: str, ip: str, ttl: float) -> list[DomainRecord] | None:
        row = self.db.execute(
            "SELECT fetched_at, records FROM cache WHERE source=? AND ip=?", (source, ip)
        ).fetchone()
        if row is None or time.time() - row["fetched_at"] > ttl:
            return None
        return [DomainRecord(**r) for r in json.loads(row["records"])]

    def cache_put(self, source: str, ip: str, records: list[DomainRecord]) -> None:
        payload = json.dumps([r.__dict__ for r in records])
        self.db.execute(
            "INSERT OR REPLACE INTO cache (source, ip, fetched_at, records) VALUES (?,?,?,?)",
            (source, ip, time.time(), payload),
        )
        self.db.commit()

    def cache_clear(self, older_than: float | None = None) -> int:
        if older_than is None:
            cur = self.db.execute("DELETE FROM cache")
        else:
            cur = self.db.execute("DELETE FROM cache WHERE fetched_at < ?", (time.time() - older_than,))
        self.db.commit()
        return cur.rowcount

    def cache_stats(self) -> list[tuple[str, int]]:
        rows = self.db.execute(
            "SELECT source, COUNT(*) AS n FROM cache GROUP BY source ORDER BY source"
        ).fetchall()
        return [(r["source"], r["n"]) for r in rows]

    # ================================================================ scans

    def create_scan(self, ips: list[str], options: dict, label: str | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO scans (created_at, status, label, options) VALUES (?, 'running', ?, ?)",
            (time.time(), label, json.dumps(options)),
        )
        scan_id = cur.lastrowid
        self.db.executemany(
            "INSERT OR IGNORE INTO scan_ips (scan_id, pos, ip, v2) VALUES (?,?,?,1)",
            ((scan_id, i, ip) for i, ip in enumerate(ips)),
        )
        self.db.commit()
        return scan_id

    def save_result(self, scan_id: int, result: IPResult, commit: bool = True) -> None:
        data = result.to_dict()
        domains = data.pop("domains")
        info = result.info or {}
        n_active = sum(1 for d in domains if d["status"] == "active")
        self.db.execute("DELETE FROM scan_domains WHERE scan_id=? AND ip=?", (scan_id, result.ip))
        self.db.executemany(
            """INSERT INTO scan_domains (scan_id, ip, domain, root, status, confidence, title, tech, data)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                (
                    scan_id, result.ip, d["domain"], d.get("root"), d["status"], d.get("confidence") or 0,
                    (d.get("http") or {}).get("title"),
                    " ".join((d.get("http") or {}).get("tech") or []) or None,
                    json.dumps(d, ensure_ascii=False),
                )
                for d in domains
            ),
        )
        self.db.execute(
            """UPDATE scan_ips SET done=1, v2=1, result=?, n_domains=?, n_active=?, n_errors=?,
                      asn=?, provider=?, category=?, hosting=?
               WHERE scan_id=? AND ip=?""",
            (
                json.dumps(data, ensure_ascii=False), len(domains), n_active, len(result.errors),
                info.get("asn"), info.get("provider"), info.get("category"), info.get("hosting"),
                scan_id, result.ip,
            ),
        )
        if commit:
            self.db.commit()

    def _ensure_indexed(self, scan_id: int) -> None:
        """Move domains of scans saved by older versions into scan_domains (once)."""
        old = self.db.execute(
            "SELECT result FROM scan_ips WHERE scan_id=? AND done=1 AND v2=0", (scan_id,)
        ).fetchall()
        if not old:
            return
        for row in old:
            self.save_result(scan_id, IPResult.from_dict(json.loads(row["result"])), commit=False)
        self.db.commit()

    def set_status(self, scan_id: int, status: str) -> None:
        finished = time.time() if status == "done" else None
        self.db.execute("UPDATE scans SET status=?, finished_at=? WHERE id=?", (status, finished, scan_id))
        self.db.commit()

    def scanned_ips(self, exclude_scan: int | None = None) -> set[str]:
        """IPs that finished in any earlier scan."""
        rows = self.db.execute(
            "SELECT DISTINCT ip FROM scan_ips WHERE done=1 AND scan_id != ?", (exclude_scan or -1,)
        )
        return {r["ip"] for r in rows}

    def pending_ips(self, scan_id: int) -> list[str]:
        rows = self.db.execute(
            "SELECT ip FROM scan_ips WHERE scan_id=? AND done=0 ORDER BY pos", (scan_id,)
        ).fetchall()
        return [r["ip"] for r in rows]

    def iter_results(self, scan_id: int) -> Iterator[IPResult]:
        """Stream finished IPs (in input order) with their domains, one IP at a time."""
        self._ensure_indexed(scan_id)
        cur = self.db.execute(
            """SELECT i.ip AS ip, i.result AS result, d.data AS data
               FROM scan_ips i LEFT JOIN scan_domains d ON d.scan_id = i.scan_id AND d.ip = i.ip
               WHERE i.scan_id=? AND i.done=1
               ORDER BY i.pos, d.domain""",
            (scan_id,),
        )
        current: dict | None = None
        for row in cur:
            if current is None or current["ip"] != row["ip"]:
                if current is not None:
                    yield IPResult.from_dict(current)
                current = json.loads(row["result"])
                current["domains"] = []
            if row["data"]:
                current["domains"].append(json.loads(row["data"]))
        if current is not None:
            yield IPResult.from_dict(current)

    def results(self, scan_id: int) -> list[IPResult]:
        return list(self.iter_results(scan_id))

    def get_scan(self, scan_id: int) -> dict | None:
        row = self.db.execute(
            """SELECT s.*, COUNT(i.ip) AS total, COALESCE(SUM(i.done), 0) AS done
               FROM scans s LEFT JOIN scan_ips i ON i.scan_id = s.id
               WHERE s.id=? GROUP BY s.id""",
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["options"] = json.loads(d["options"])
        return d

    def list_scans(self, limit: int = 20) -> list[dict]:
        rows = self.db.execute(
            """SELECT s.id, s.created_at, s.status, s.label,
                      COUNT(i.ip) AS total, COALESCE(SUM(i.done), 0) AS done
               FROM scans s LEFT JOIN scan_ips i ON i.scan_id = s.id
               GROUP BY s.id ORDER BY s.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_resumable(self) -> int | None:
        row = self.db.execute(
            "SELECT id FROM scans WHERE status != 'done' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["id"] if row else None

    def delete_scan(self, scan_id: int) -> bool:
        cur = self.db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        self.db.commit()
        return cur.rowcount > 0

    # ================================================================ queries (paging / summaries)

    def summary(self, scan_id: int) -> dict:
        self._ensure_indexed(scan_id)
        ip = self.db.execute(
            """SELECT COUNT(*) AS ips, COALESCE(SUM(n_errors), 0) AS errors,
                      COALESCE(SUM(category = 'cdn'), 0) AS cdn_ips,
                      COALESCE(SUM(n_domains > 0), 0) AS ips_with_domains
               FROM scan_ips WHERE scan_id=? AND done=1""",
            (scan_id,),
        ).fetchone()
        dom = self.db.execute(
            """SELECT COUNT(*) AS rows, COUNT(DISTINCT domain) AS domains, COUNT(DISTINCT root) AS roots,
                      COALESCE(SUM(status = 'active'), 0) AS active
               FROM scan_domains WHERE scan_id=?""",
            (scan_id,),
        ).fetchone()
        providers = [
            r["provider"] for r in self.db.execute(
                "SELECT DISTINCT provider FROM scan_ips WHERE scan_id=? AND category='cdn' AND provider IS NOT NULL",
                (scan_id,),
            )
        ]
        return {**dict(ip), **dict(dom), "cdn_providers": providers}

    def error_summary(self, scan_id: int) -> dict[str, int]:
        """Errors per source across the scan."""
        counts: dict[str, int] = {}
        for row in self.db.execute(
            "SELECT result FROM scan_ips WHERE scan_id=? AND done=1 AND n_errors > 0", (scan_id,)
        ):
            for src in (json.loads(row["result"]).get("errors") or {}):
                counts[src] = counts.get(src, 0) + 1
        return counts

    def _domain_where(self, scan_id: int, ip: str | None, status: str | None, search: str | None):
        where, args = ["scan_id=?"], [scan_id]
        if ip:
            where.append("ip=?")
            args.append(ip)
        if status and status != "all":
            where.append("status=?")
            args.append(status)
        if search and search.strip():
            q = _like(search.strip().lower())
            where.append("(domain LIKE ? ESCAPE '\\' OR lower(title) LIKE ? ESCAPE '\\' OR lower(tech) LIKE ? ESCAPE '\\')")
            args += [q, q, q]
        return " AND ".join(where), args

    def status_counts(self, scan_id: int, ip: str | None = None, search: str | None = None) -> dict[str, int]:
        where, args = self._domain_where(scan_id, ip, None, search)
        rows = self.db.execute(f"SELECT status, COUNT(*) AS n FROM scan_domains WHERE {where} GROUP BY status", args)
        counts = {r["status"]: r["n"] for r in rows}
        counts["all"] = sum(counts.values())
        return counts

    def query_domains(self, scan_id: int, ip: str | None = None, status: str | None = None,
                      search: str | None = None, offset: int = 0, limit: int = 200) -> tuple[list[dict], int]:
        self._ensure_indexed(scan_id)
        where, args = self._domain_where(scan_id, ip, status, search)
        total = self.db.execute(f"SELECT COUNT(*) FROM scan_domains WHERE {where}", args).fetchone()[0]
        rows = self.db.execute(
            f"SELECT ip, data FROM scan_domains WHERE {where} ORDER BY domain, ip LIMIT ? OFFSET ?",
            [*args, int(limit), int(offset)],
        ).fetchall()
        out = []
        for r in rows:
            d = json.loads(r["data"])
            d["ip"] = r["ip"]
            out.append(d)
        return out, total

    def query_roots(self, scan_id: int, ip: str | None = None, status: str | None = None,
                    search: str | None = None, offset: int = 0, limit: int = 200) -> tuple[list[dict], int]:
        self._ensure_indexed(scan_id)
        where, args = self._domain_where(scan_id, ip, status, search)
        total = self.db.execute(
            f"SELECT COUNT(DISTINCT COALESCE(root, domain)) FROM scan_domains WHERE {where}", args
        ).fetchone()[0]
        rows = self.db.execute(
            f"""SELECT COALESCE(root, domain) AS root, COUNT(DISTINCT domain) AS names,
                       substr(group_concat(DISTINCT domain), 1, 400) AS examples
                FROM scan_domains WHERE {where}
                GROUP BY COALESCE(root, domain) ORDER BY names DESC, root LIMIT ? OFFSET ?""",
            [*args, int(limit), int(offset)],
        ).fetchall()
        return [
            {"root": r["root"], "names": r["names"], "examples": (r["examples"] or "").split(",")[:4]}
            for r in rows
        ], total

    def domain_names(self, scan_id: int, ip: str | None = None, status: str | None = None,
                     search: str | None = None, roots: bool = False, limit: int | None = None) -> list[str]:
        self._ensure_indexed(scan_id)
        where, args = self._domain_where(scan_id, ip, status, search)
        col = "COALESCE(root, domain)" if roots else "domain"
        sql = f"SELECT DISTINCT {col} AS n FROM scan_domains WHERE {where} ORDER BY n"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [r["n"] for r in self.db.execute(sql, args)]

    def top_ips(self, scan_id: int | None, n: int = 100, min_domains: int = 1,
                exclude_cdn: bool = True) -> list[dict]:
        """IPs with the most domains (one scan, or every scan when scan_id is None)."""
        where, args = ["done=1", "n_domains >= ?"], [int(min_domains)]
        if scan_id is not None:
            self._ensure_indexed(scan_id)
            where.append("scan_id=?")
            args.append(scan_id)
        if exclude_cdn:
            where.append("COALESCE(category, '') != 'cdn'")
        rows = self.db.execute(
            f"""SELECT ip, MAX(n_domains) AS n_domains, MAX(provider) AS provider, MAX(asn) AS asn,
                       MAX(hosting) AS hosting
                FROM scan_ips WHERE {' AND '.join(where)}
                GROUP BY ip ORDER BY n_domains DESC, ip LIMIT ?""",
            [*args, int(n)],
        ).fetchall()
        return [dict(r) for r in rows]

    def list_ips(self, scan_id: int, search: str | None = None, offset: int = 0,
                 limit: int = 200, order: str = "pos") -> tuple[list[dict], int]:
        self._ensure_indexed(scan_id)
        where, args = ["scan_id=?", "done=1"], [scan_id]
        if search and search.strip():
            q = _like(search.strip().lower())
            where.append("(ip LIKE ? ESCAPE '\\' OR lower(provider) LIKE ? ESCAPE '\\' OR CAST(asn AS TEXT) LIKE ? ESCAPE '\\')")
            args += [q, q, q]
        w = " AND ".join(where)
        total = self.db.execute(f"SELECT COUNT(*) FROM scan_ips WHERE {w}", args).fetchone()[0]
        order_sql = "n_domains DESC, pos" if order == "domains" else "pos"
        rows = self.db.execute(
            f"""SELECT ip, n_domains, n_active, n_errors, asn, provider, category, hosting, result
                FROM scan_ips WHERE {w} ORDER BY {order_sql} LIMIT ? OFFSET ?""",
            [*args, int(limit), int(offset)],
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["errors"] = (json.loads(d.pop("result") or "{}").get("errors")) or {}
            out.append(d)
        return out, total
