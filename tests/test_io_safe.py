# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for bounded, traversal-safe reads (T-104)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpscan.io_safe import (
    FileAccessError,
    FileTooLargeError,
    UnsafeSymlinkError,
    safe_read_text,
)


def test_reads_normal_file(tmp_path: Path) -> None:
    f = tmp_path / "config.json"
    f.write_text('{"ok": true}', encoding="utf-8")
    assert safe_read_text(f, root=tmp_path) == '{"ok": true}'


def test_rejects_oversized_file(tmp_path: Path) -> None:
    f = tmp_path / "big.json"
    f.write_text("x" * 100, encoding="utf-8")
    with pytest.raises(FileTooLargeError):
        safe_read_text(f, root=tmp_path, max_bytes=10)


def test_missing_file_raises_access_error(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError):
        safe_read_text(tmp_path / "nope.json", root=tmp_path)


def test_rejects_path_escaping_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    with pytest.raises(UnsafeSymlinkError):
        safe_read_text(outside, root=root)


def test_rejects_symlink_escaping_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = root / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/run")
    with pytest.raises(UnsafeSymlinkError):
        safe_read_text(link, root=root)


def test_binary_file_degrades_without_crashing(tmp_path: Path) -> None:
    f = tmp_path / "blob.bin"
    f.write_bytes(b"\xff\xfe\x00\x01")
    # Must not raise — invalid UTF-8 is replaced, parse failure is handled upstream.
    out = safe_read_text(f, root=tmp_path)
    assert isinstance(out, str)
