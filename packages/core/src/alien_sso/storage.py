"""Pluggable storage for tokens and PKCE state.

Replaces the JS SDK's hard dependency on `localStorage`/`sessionStorage`.
Provides an in-memory default and a JSON-on-disk variant. Implement the
`Storage` protocol to plug in your own (Redis, encrypted DB, etc.).
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Optional, Protocol


class Storage(Protocol):
    """Minimal key-value contract — mirrors the JS Storage API."""

    def get(self, key: str) -> Optional[str]: ...
    def set(self, key: str, value: str) -> None: ...
    def delete(self, key: str) -> None: ...
    def clear(self) -> None: ...


class MemoryStorage:
    """Process-local, thread-safe storage. The default."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._data[key] = value

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class FileStorage:
    """JSON-on-disk storage. Useful for CLI agents that should survive restarts.

    Not concurrency-safe across processes — use a real KV store for that. The
    file is written with mode 0o600 to avoid leaking tokens to other users.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()

    def _read(self) -> dict[str, str]:
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    return {}
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._path)

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            return self._read().get(key)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            data = self._read()
            data[key] = value
            self._write(data)

    def delete(self, key: str) -> None:
        with self._lock:
            data = self._read()
            data.pop(key, None)
            self._write(data)

    def clear(self) -> None:
        with self._lock:
            try:
                self._path.unlink()
            except FileNotFoundError:
                pass
