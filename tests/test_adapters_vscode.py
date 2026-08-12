# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the VS Code host adapter (ADR-4; native MCP support)."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.adapters.vscode import VSCodeAdapter


def test_parses_servers_key() -> None:
    # VS Code uses "servers" (not "mcpServers").
    raw = json.dumps(
        {
            "servers": {"svc": {"command": "npx", "args": ["-y", "tool@1.0.0"], "env": {"K": "v"}}},
            "inputs": [{"id": "api-key", "type": "promptString"}],
        }
    )
    cfg = VSCodeAdapter().parse("/w/.vscode/mcp.json", raw)
    assert cfg.parse_error is None
    assert [s.name for s in cfg.servers] == ["svc"]
    assert cfg.servers[0].command == "npx"
    assert cfg.servers[0].env == (("K", "v"),)
    assert cfg.allow_permissions == ()  # VS Code has no permission allow-list here


def test_accepts_mcpservers_key_for_tolerance() -> None:
    raw = json.dumps({"mcpServers": {"svc": {"command": "node", "args": ["s.js"]}}})
    cfg = VSCodeAdapter().parse("/w/.vscode/mcp.json", raw)
    assert [s.name for s in cfg.servers] == ["svc"]


def test_http_server_without_command_is_tolerated() -> None:
    # A remote (http/sse) server has a url and no command — must not crash.
    raw = json.dumps({"servers": {"remote": {"type": "http", "url": "http://127.0.0.1:9"}}})
    cfg = VSCodeAdapter().parse("/w/.vscode/mcp.json", raw)
    assert cfg.parse_error is None
    assert cfg.servers[0].name == "remote"
    assert cfg.servers[0].command is None


def test_parses_jsonc_with_comments() -> None:
    # mcp.json is JSONC — a config with comments + a trailing comma must parse.
    raw = """
    {
      // project MCP servers
      "servers": {
        "svc": { "command": "node", "args": ["s.js"], },
      },
    }
    """
    cfg = VSCodeAdapter().parse("/w/.vscode/mcp.json", raw)
    assert cfg.parse_error is None
    assert [s.name for s in cfg.servers] == ["svc"]


def test_never_raises_on_bad_json() -> None:
    cfg = VSCodeAdapter().parse("/w/.vscode/mcp.json", "{nope")
    assert cfg.parse_error is not None
    assert cfg.servers == ()


def test_non_object_root_is_parse_error() -> None:
    cfg = VSCodeAdapter().parse("/w/.vscode/mcp.json", "42")
    assert cfg.parse_error == "config root is not an object"


def test_non_dict_server_spec_is_skipped() -> None:
    # A malformed entry (server value is a string, not an object) is ignored,
    # not a crash; well-formed siblings still parse.
    raw = json.dumps({"servers": {"bad": "oops", "good": {"command": "node"}}})
    cfg = VSCodeAdapter().parse("/w/.vscode/mcp.json", raw)
    assert cfg.parse_error is None
    assert [s.name for s in cfg.servers] == ["good"]


def test_default_config_paths_is_user_mcp_json() -> None:
    paths = [str(p) for p in VSCodeAdapter().default_config_paths("Linux", {"HOME": "/home/j"})]
    assert paths == ["/home/j/.config/Code/User/mcp.json"]


def test_project_config_path_is_dot_vscode() -> None:
    paths = VSCodeAdapter().project_config_paths(Path("/proj"))
    assert paths == [Path("/proj/.vscode/mcp.json")]
