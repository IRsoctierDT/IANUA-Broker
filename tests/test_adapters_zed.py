# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Zed host adapter (ADR-4; native MCP support)."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.adapters.zed import ZedAdapter


def test_parses_context_servers_map() -> None:
    raw = json.dumps(
        {
            "context_servers": {
                "svc": {"command": "npx", "args": ["-y", "tool@1.0.0"], "env": {"K": "v"}}
            }
        }
    )
    cfg = ZedAdapter().parse("/p/.zed/settings.json", raw)
    assert cfg.parse_error is None
    assert [s.name for s in cfg.servers] == ["svc"]
    assert cfg.servers[0].command == "npx"
    assert cfg.servers[0].env == (("K", "v"),)
    assert cfg.allow_permissions == ()


def test_parses_jsonc_with_comments_and_trailing_commas() -> None:
    # Zed settings.json is JSONC — a real-world file with comments must parse.
    raw = """
    {
      // MCP servers for this project
      "context_servers": {
        "db": {
          "command": "uvx",
          "args": ["mcp-server-sqlite",], /* trailing comma + block comment */
        },
      },
    }
    """
    cfg = ZedAdapter().parse("/p/.zed/settings.json", raw)
    assert cfg.parse_error is None
    assert [s.name for s in cfg.servers] == ["db"]
    assert cfg.servers[0].command == "uvx"


def test_remote_server_without_command_is_tolerated() -> None:
    raw = json.dumps({"context_servers": {"remote": {"url": "https://example.com/mcp"}}})
    cfg = ZedAdapter().parse("/p/.zed/settings.json", raw)
    assert cfg.parse_error is None
    assert cfg.servers[0].name == "remote"
    assert cfg.servers[0].command is None


def test_never_raises_on_bad_json() -> None:
    cfg = ZedAdapter().parse("/p/.zed/settings.json", "{nope")
    assert cfg.parse_error is not None
    assert cfg.servers == ()


def test_non_object_root_is_parse_error() -> None:
    cfg = ZedAdapter().parse("/p/.zed/settings.json", "42")
    assert cfg.parse_error == "config root is not an object"


def test_settings_without_context_servers_yields_no_servers() -> None:
    # A normal Zed settings.json with no MCP servers must be silent, not an error.
    cfg = ZedAdapter().parse("/p/.zed/settings.json", json.dumps({"theme": "One Dark"}))
    assert cfg.parse_error is None
    assert cfg.servers == ()


def test_default_config_paths_uses_dot_config_on_posix() -> None:
    paths = [str(p) for p in ZedAdapter().default_config_paths("Darwin", {"HOME": "/Users/j"})]
    assert paths == ["/Users/j/.config/zed/settings.json"]  # macOS uses ~/.config, not ~/Library


def test_project_config_path_is_dot_zed() -> None:
    assert ZedAdapter().project_config_paths(Path("/proj")) == [Path("/proj/.zed/settings.json")]
