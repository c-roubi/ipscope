"""PyInstaller entry for the command line tool (ipscope.exe)."""
import sys

from ipscope.cli import app

if __name__ == "__main__":
    # rich prints box characters; make sure an old Windows console code page can't crash it
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    app(prog_name="ipscope")
