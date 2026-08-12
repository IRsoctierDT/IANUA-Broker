# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Cursor host adapter (ADR-4 second adapter)."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.adapters.cursor import CursorAdapter


def test_parses_mcp_servers() -> None:
    raw = json.dumps(
        {
            "mcpServers": {
                "db": {"command": "npx", "args": ["-y", "db-mcp@1.0.0"], "env": {"K": "v"}},
                "fetch": {"command": "uvx", "args": ["fetch-mcp"]},
            }
        }
    )
    cfg = CursorAdapter().parse("/c/.cursor/mcp.json", raw)
    assert cfg.parse_error is None
    assert {s.name for s in cfg.servers} == {"db", "fetch"}
    db = next(s for s in cfg.servers if s.name == "db")
    assert db.command == "npx"
    assert db.args == ("-y", "db-mcp@1.0.0")
    assert db.env == (("K", "v"),)
    # Cursor has no permission allow-list.
    assert cfg.allow_permissions == ()


def test_never_raises_on_bad_json() -> None:
    cfg = CursorAdapter().parse("/c/.cursor/mcp.json", "{not json")
    assert cfg.parse_error is not None
    assert cfg.servers == ()


def test_non_object_root_is_parse_error() -> None:
    cfg = CursorAdapter().parse("/c/.cursor/mcp.json", "[]")
    assert cfg.parse_error == "config root is not an object"
    assert cfg.servers == ()


def test_default_config_paths_is_global_cursor_file() -> None:
    paths = [str(p) for p in CursorAdapter().default_config_paths("Linux", {"HOME": "/home/j"})]
    assert paths == ["/home/j/.cursor/mcp.json"]


def test_project_config_path_is_dot_cursor() -> None:
    paths = CursorAdapter().project_config_paths(Path("/proj"))
    assert [p.as_posix() for p in paths] == ["/proj/.cursor/mcp.json"]
