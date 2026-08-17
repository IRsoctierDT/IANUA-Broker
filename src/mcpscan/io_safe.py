# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Bounded, traversal-safe file reading (ticket T-104).

Every config file the tool reads goes through here so that malformed, oversized,
symlinked-outside-root, or permission-denied files become typed errors (which the
engine turns into findings) instead of crashes or security issues.
"""

from __future__ import annotations

from pathlib import Path

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB (NFR-S3 cap)


class SafeReadError(Exception):
    """Base class for all safe-read failures."""


class FileTooLargeError(SafeReadError):
    """The file exceeds the configured size cap."""


class UnsafeSymlinkError(SafeReadError):
    """The resolved path escapes the permitted root."""


class FileAccessError(SafeReadError):
    """The file could not be read (missing or permission denied)."""


def safe_read_text(
    path: Path,
    root: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> str:
    """Read ``path`` as UTF-8 text, enforcing safety invariants.

    Args:
        path: The file to read.
        root: The directory the resolved file must stay within (no escaping via
            symlink or ``..``).
        max_bytes: Hard cap on file size; larger files raise
            :class:`FileTooLargeError` without being read.

    Returns:
        The file contents as text (invalid UTF-8 bytes are replaced, never
        raised, so a binary file degrades to a parse error upstream rather than a
        crash).

    Raises:
        UnsafeSymlinkError: If the resolved path is outside ``root``.
        FileTooLargeError: If the file exceeds ``max_bytes``.
        FileAccessError: If the file is missing, unreadable, or is not a regular
            file (a FIFO, device, or socket).
    """
    try:
        resolved_root = root.resolve()
        resolved = path.resolve()
    except (OSError, RuntimeError) as exc:
        # A symlink loop raises here (``RuntimeError`` on POSIX, ``OSError``
        # ELOOP elsewhere) before any invariant is checked. Callers catch
        # SafeReadError only, so an unwrapped error would crash the scan a
        # planted loop is meant to survive (NFR-S3).
        raise FileAccessError(f"{path} cannot be resolved: {exc}") from exc

    if not resolved.is_relative_to(resolved_root):
        raise UnsafeSymlinkError(f"{path} resolves outside {root}")

    try:
        size = resolved.stat().st_size
    except OSError as exc:  # missing, permission denied, etc.
        raise FileAccessError(str(exc)) from exc

    if not resolved.is_file():
        # Not a regular file: a directory, or — the hostile case — a FIFO,
        # device, or socket planted where a config is expected. ``st_size`` is 0
        # for those, so the cap below cannot stop them and ``read_text`` would
        # block forever on a FIFO with no writer (a config-planted hang, the
        # DoS row of the threat model). Refuse by type instead.
        raise FileAccessError(f"{path} is not a regular file")

    if size > max_bytes:
        raise FileTooLargeError(f"{path} is {size} bytes (cap {max_bytes})")

    try:
        return resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise FileAccessError(str(exc)) from exc
