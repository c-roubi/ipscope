"""Where IPScope keeps its data (~/.ipscope, or $IPSCOPE_HOME)."""

from __future__ import annotations

import os
from pathlib import Path


def home_dir() -> Path:
    p = Path(os.environ.get("IPSCOPE_HOME") or (Path.home() / ".ipscope"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_path() -> Path:
    return home_dir() / "ipscope.db"
