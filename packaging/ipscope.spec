# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build for IPScope.

Produces one folder (dist/IPScope) with two programs that share the same files:
  IPScope.exe  - the desktop app (no console window)
  ipscope.exe  - the command line tool

Build:  pyinstaller packaging/ipscope.spec --noconfirm
Set IPSCOPE_NO_GUI=1 to build only the CLI (e.g. on a machine without pywebview).
"""
import os
import re
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
PKG = os.path.join(ROOT, "packaging")
WITH_GUI = os.environ.get("IPSCOPE_NO_GUI") != "1"
IS_WIN = sys.platform.startswith("win")

with open(os.path.join(ROOT, "ipscope", "__init__.py"), encoding="utf-8") as f:
    VERSION = re.search(r'__version__ = "([^"]+)"', f.read()).group(1)

datas = [(os.path.join(ROOT, "ipscope", "gui", "web"), os.path.join("ipscope", "gui", "web"))]
datas += collect_data_files("tldextract")           # bundled Public Suffix List snapshot (offline)
datas += copy_metadata("keyring")                    # keyring finds its backends via entry points
datas += copy_metadata("typer") + copy_metadata("rich")

hidden = collect_submodules("dns")                   # dnspython loads backends dynamically
hidden += [
    "keyring.backends.Windows", "keyring.backends.macOS", "keyring.backends.SecretService",
    "keyring.backends.fail", "keyring.backends.null", "keyring.backends.chainer",
]
excludes = ["tkinter", "matplotlib", "numpy", "pandas", "PIL", "pytest", "IPython"]

version_file = None
if IS_WIN:
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct, VSVersionInfo,
    )
    nums = tuple(int(x) for x in (VERSION.split(".") + ["0", "0", "0"])[:4])
    version_file = VSVersionInfo(
        ffi=FixedFileInfo(filevers=nums, prodvers=nums),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("CompanyName", "IPScope"),
                StringStruct("FileDescription", "IPScope - reverse IP lookup"),
                StringStruct("FileVersion", VERSION),
                StringStruct("ProductName", "IPScope"),
                StringStruct("ProductVersion", VERSION),
                StringStruct("OriginalFilename", "IPScope.exe"),
            ])]),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )

ICON = os.path.join(PKG, "ipscope.ico")


def build(script, name, console, extra_hidden=()):
    a = Analysis(
        [os.path.join(PKG, script)],
        pathex=[ROOT],
        datas=datas,
        hiddenimports=hidden + list(extra_hidden),
        excludes=excludes,
        noarchive=False,
    )
    pyz = PYZ(a.pure)
    exe = EXE(
        pyz, a.scripts, [],
        exclude_binaries=True,
        name=name,
        console=console,
        icon=ICON,
        version=version_file,
        upx=False,                 # UPX-packed exes trigger more antivirus false positives
    )
    return a, exe


parts = []
a_cli, exe_cli = build("entry_cli.py", "ipscope", console=True)
parts += [exe_cli, a_cli.binaries, a_cli.datas]

if WITH_GUI:
    gui_hidden = collect_submodules("webview") + ["clr", "proxy_tools", "bottle"]
    a_gui, exe_gui = build("entry_gui.py", "IPScope", console=False, extra_hidden=gui_hidden)
    parts += [exe_gui, a_gui.binaries, a_gui.datas]

coll = COLLECT(*parts, upx=False, name="IPScope")
