"""Write results as TXT, CSV or JSON (picked from the file extension).

Accepts any iterable of IPResult (e.g. Store.iter_results) and streams it to disk,
so exporting a huge scan doesn't need it all in memory.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path

from ipscope.models import IPResult, Status

CSV_FIELDS = [
    "ip", "asn", "provider", "hosting",
    "domain", "root_domain", "status", "confidence", "sources",
    "first_seen", "last_seen", "resolved_ips",
    "http_status", "final_url", "title", "server", "tech",
]


def export(
    results: Iterable[IPResult],
    path: str | Path,
    only_active: bool = False,
    roots_only: bool = False,
    include_sources: bool = True,
) -> int:
    """Write results; returns the number of rows (or unique names for .txt).

    include_sources=False drops source names (and per-source errors) from CSV/JSON.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ext = path.suffix.lower()
    keep = (lambda d: d.status == Status.ACTIVE) if only_active else (lambda d: True)

    if ext == ".csv":
        n = 0
        # utf-8-sig so Excel on Windows opens Arabic titles correctly
        fields = CSV_FIELDS if include_sources else [c for c in CSV_FIELDS if c != "sources"]
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(fields)
            for r in results:
                for d in r.sorted_domains():
                    if not keep(d):
                        continue
                    h = d.http or {}
                    row = [
                        r.ip, r.info.get("asn") or "", r.info.get("provider") or "", r.info.get("hosting") or "",
                        d.domain, d.root or "", d.status.value, d.confidence, ";".join(sorted(d.sources)),
                        d.first_seen or "", d.last_seen or "", ";".join(d.resolved_ips),
                        h.get("status") or "", h.get("url") or "", h.get("title") or "",
                        h.get("server") or "", ";".join(h.get("tech") or []),
                    ]
                    if not include_sources:
                        del row[8]
                    w.writerow(row)
                    n += 1
        return n

    if ext == ".json":
        n = 0
        with path.open("w", encoding="utf-8") as f:
            f.write("[")
            for i, r in enumerate(results):
                item = r.to_dict()
                if not include_sources:
                    item.pop("errors", None)
                    for d in item["domains"]:
                        d.pop("sources", None)
                if only_active:
                    item["domains"] = [d for d in item["domains"] if d["status"] == Status.ACTIVE.value]
                n += len(item["domains"])
                f.write(("," if i else "") + "\n  " + json.dumps(item, ensure_ascii=False))
            f.write("\n]\n")
        return n

    # default: plain list of unique domains (or root domains)
    names: set[str] = set()
    for r in results:
        for d in r.domains.values():
            if keep(d):
                names.add((d.root or d.domain) if roots_only else d.domain)
    ordered = sorted(names)
    path.write_text("\n".join(ordered) + ("\n" if ordered else ""), encoding="utf-8")
    return len(ordered)


def export_scan(store, scan_id: int, path: str | Path, only_active: bool = False, roots_only: bool = False,
                include_sources: bool = True) -> int:
    """Export a saved scan straight from the database (streamed; TXT via SQL DISTINCT)."""
    path = Path(path)
    if path.suffix.lower() not in (".csv", ".json"):
        names = store.domain_names(scan_id, status="active" if only_active else None, roots=roots_only)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(names) + ("\n" if names else ""), encoding="utf-8")
        return len(names)
    return export(store.iter_results(scan_id), path, only_active=only_active, roots_only=roots_only,
                  include_sources=include_sources)
