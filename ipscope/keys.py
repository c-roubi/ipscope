"""API key storage.

Lookup order for a source:  environment variable  ->  OS keyring  ->  keys.json fallback.
Several keys per source are allowed (comma-separated) and are rotated when one is
rejected or rate-limited.

The OS keyring is Windows Credential Manager / macOS Keychain / Secret Service.
If no keyring is available, keys go to ~/.ipscope/keys.json with owner-only permissions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ipscope.paths import home_dir

SERVICE = "ipscope"


def split_keys(value: str | None) -> list[str]:
    return [k.strip() for k in (value or "").split(",") if k.strip()]


def mask(key: str) -> str:
    return key[:4] + "…" + key[-4:] if len(key) > 10 else "…" * 3


def _usable_keyring():
    try:
        import keyring
        from keyring.backends import fail
    except ImportError:
        return None
    try:
        kr = keyring.get_keyring()
    except Exception:
        return None
    if isinstance(kr, fail.Keyring) or getattr(kr, "backends", None) == []:
        return None
    return keyring


class KeyStore:
    def __init__(self, home: Path | None = None, use_keyring: bool = True):
        self.home = Path(home) if home else home_dir()
        self.file = self.home / "keys.json"
        if os.environ.get("IPSCOPE_NO_KEYRING"):
            use_keyring = False
        self._kr = _usable_keyring() if use_keyring else None

    @property
    def backend(self) -> str:
        return "os-keyring" if self._kr else f"file ({self.file})"

    # ---------- file fallback ----------

    def _load_file(self) -> dict[str, str]:
        try:
            return json.loads(self.file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_file(self, data: dict[str, str]) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        tmp = self.file.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.file)
        try:
            os.chmod(self.file, 0o600)
        except OSError:
            pass

    # ---------- public API ----------

    def get(self, name: str) -> list[str]:
        if self._kr:
            try:
                return split_keys(self._kr.get_password(SERVICE, name))
            except Exception:
                pass
        return split_keys(self._load_file().get(name))

    def set(self, name: str, keys: list[str]) -> None:
        value = ",".join(dict.fromkeys(k.strip() for k in keys if k.strip()))
        if self._kr:
            try:
                self._kr.set_password(SERVICE, name, value)
                return
            except Exception:
                self._kr = None  # fall back to file
        data = self._load_file()
        data[name] = value
        self._save_file(data)

    def add(self, name: str, key: str) -> int:
        keys = self.get(name)
        if key not in keys:
            keys.append(key)
        self.set(name, keys)
        return len(keys)

    def delete(self, name: str) -> bool:
        found = False
        if self._kr:
            try:
                if self._kr.get_password(SERVICE, name) is not None:
                    self._kr.delete_password(SERVICE, name)
                    found = True
            except Exception:
                pass
        data = self._load_file()
        if name in data:
            del data[name]
            self._save_file(data)
            found = True
        return found

    def resolve(self, name: str, env_var: str | None) -> tuple[list[str], str]:
        """Return (keys, where-they-came-from)."""
        if env_var and split_keys(os.environ.get(env_var)):
            return split_keys(os.environ.get(env_var)), f"env:{env_var}"
        keys = self.get(name)
        return keys, ("store" if keys else "")

    def resolve_all(self, registry) -> dict[str, list[str]]:
        return {
            name: self.resolve(name, cls.key_env)[0]
            for name, cls in registry.items()
            if cls.key_env
        }
