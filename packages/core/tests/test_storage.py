"""Tests for the Storage backends — no JS counterpart, but worth covering."""

from __future__ import annotations

import os
from pathlib import Path

from alien_sso.storage import FileStorage, MemoryStorage


def test_memory_storage_basic_lifecycle():
    s = MemoryStorage()
    assert s.get("k") is None
    s.set("k", "v")
    assert s.get("k") == "v"
    s.delete("k")
    assert s.get("k") is None


def test_memory_storage_clear():
    s = MemoryStorage()
    s.set("a", "1")
    s.set("b", "2")
    s.clear()
    assert s.get("a") is None
    assert s.get("b") is None


def test_file_storage_round_trip(tmp_path: Path):
    path = tmp_path / "store.json"
    s = FileStorage(path)
    s.set("token", "abc")
    assert path.exists()
    # Verify on-disk perms
    assert oct(os.stat(path).st_mode)[-3:] == "600"

    # Re-open from disk
    s2 = FileStorage(path)
    assert s2.get("token") == "abc"
    s2.delete("token")
    assert s2.get("token") is None


def test_file_storage_clear_removes_file(tmp_path: Path):
    path = tmp_path / "store.json"
    s = FileStorage(path)
    s.set("k", "v")
    s.clear()
    assert not path.exists()
    # Idempotent
    s.clear()


def test_file_storage_handles_missing_parent_dir(tmp_path: Path):
    path = tmp_path / "deep" / "nested" / "store.json"
    s = FileStorage(path)
    s.set("k", "v")
    assert path.exists()
    assert s.get("k") == "v"
