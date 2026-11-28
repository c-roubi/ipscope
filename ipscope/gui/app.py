"""Desktop app entry point (pywebview)."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from ipscope.gui.api import Api


def web_dir() -> Path:
    """Location of the UI files, both from source and inside a PyInstaller build."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "ipscope" / "gui" / "web"
    return Path(__file__).parent / "web"


WEB = web_dir()


def _fatal(msg: str) -> None:
    """Show a startup error even when there is no console (windowed .exe)."""
    try:
        from ipscope.paths import home_dir
        (home_dir() / "gui-error.log").write_text(msg, encoding="utf-8")
    except Exception:
        pass
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                None, msg[-1500:] + "\n\nDetails were saved to %USERPROFILE%\\.ipscope\\gui-error.log",
                "IPScope could not start", 0x10)
            return
        except Exception:
            pass
    print(msg, file=sys.stderr)


def main() -> None:
    try:
        import webview
    except ImportError:
        _fatal("The desktop app needs pywebview:  pip install pywebview")
        raise SystemExit(1)

    try:
        api = Api()
        window = webview.create_window(
            "IPScope",
            url=str(WEB / "index.html"),
            js_api=api,
            width=1240,
            height=800,
            min_size=(980, 640),
            background_color="#1a1a1e",
            text_select=False,
        )
        api._window = window
        # The UI needs a modern engine. Without this, pywebview silently falls back
        # to the old Internet Explorer engine and shows an unstyled, dead page.
        if sys.platform.startswith("win"):
            webview.start(gui="edgechromium")
        else:
            webview.start()
    except Exception:
        hint = ""
        if sys.platform.startswith("win"):
            hint = ("\n\nIf this mentions WebView2 or EdgeChromium, install the Microsoft Edge WebView2 Runtime:\n"
                    "https://developer.microsoft.com/microsoft-edge/webview2/")
        _fatal(traceback.format_exc() + hint)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
