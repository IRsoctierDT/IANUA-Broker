# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Posture checks.

Each check is a small, single-responsibility function (Code Quality watch-item
from the review). They are pure: given parsed inputs they return findings, with
no I/O of their own.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..adapters.base import ServerDecl


@dataclass(frozen=True)
class EnvFile:
    """A parsed ``.env`` file: path plus (line_no, key, value) triples."""

    path: str
    entries: tuple[tuple[int, str, str], ...]
    mode: int | None = None  # POSIX st_mode, if known (for at-rest checks)
    git_tracked: bool | None = None


def parse_env_text(
    path: str,
    text: str,
    *,
    mode: int | None = None,
    git_tracked: bool | None = None,
) -> EnvFile:
    """Parse ``.env`` text into key/value entries (line numbers 1-based)."""
    entries: list[tuple[int, str, str]] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        entries.append((lineno, key.strip(), value.strip().strip("'\"")))
    return EnvFile(path=path, entries=tuple(entries), mode=mode, git_tracked=git_tracked)


__all__ = ["EnvFile", "ServerDecl", "parse_env_text"]
