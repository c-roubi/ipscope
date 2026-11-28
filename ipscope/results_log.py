"""Append-only list of every domain found, one per line (results.txt).

The file is never truncated or rewritten: new scans only add to it, and deleting a
scan from History leaves it alone. Domains already written during this run are not
repeated; older runs may still repeat a name.
"""

from __future__ import annotations

from pathlib import Path

from ipscope.paths import home_dir


def results_path() -> Path:
    return home_dir() / "results.txt"


class ResultsLog:
    def __init__(self, enabled: bool = True, path: Path | None = None):
        self.enabled = enabled
        self.path = path or results_path()
        self._seen: set[str] = set()
        self._fh = None

    def add(self, domains) -> None:
        if not self.enabled:
            return
        new = [d for d in domains if d and d not in self._seen]
        if not new:
            return
        if self._fh is None:
            self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        self._seen.update(new)
        self._fh.write("\n".join(new) + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
