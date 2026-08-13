# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Tests for the shared cross-platform test helpers (they are load-bearing)."""

from __future__ import annotations

from _xplatform import id_endswith


def test_id_endswith_matches_forward_slash_suffix() -> None:
    assert id_endswith("/home/u/.claude/.credentials.json", ".claude/.credentials.json")


def test_id_endswith_normalizes_windows_separators() -> None:
    # The value carries backslashes (Windows); the expected suffix uses "/".
    assert id_endswith(r"C:\Users\u\Library\Logs\Claude", "Library/Logs/Claude")
    assert id_endswith(r"telemetry://C:\Users\u\Library\Logs\Claude", "Library/Logs/Claude")


def test_id_endswith_is_false_on_a_non_suffix() -> None:
    assert not id_endswith("/home/u/other/path.json", ".claude/.credentials.json")
