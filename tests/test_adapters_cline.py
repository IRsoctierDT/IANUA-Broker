"""Unit tests for the Cline host adapter (ADR-4 fourth adapter)."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.adapters.cline import ClineAdapter


def test_parses_mcp_servers() -> None:
    raw = json.dumps(
        {"mcpServers": {"svc": {"command": "npx", "args": ["-y", "tool@1.0.0"], "env": {"K": "v"}}}}
    )
    cfg = ClineAdapter().parse("/c/cline_mcp_settings.json", raw)
    assert cfg.parse_error is None
    assert [s.name for s in cfg.servers] == ["svc"]
    assert cfg.servers[0].command == "npx"
    assert cfg.servers[0].env == (("K", "v"),)
    assert cfg.allow_permissions == ()  # Cline has no permission allow-list


def test_never_raises_on_bad_json() -> None:
    cfg = ClineAdapter().parse("/c/cline_mcp_settings.json", "{nope")
    assert cfg.parse_error is not None
    assert cfg.servers == ()


def test_non_object_root_is_parse_error() -> None:
    cfg = ClineAdapter().parse("/c/cline_mcp_settings.json", "42")
    assert cfg.parse_error == "config root is not an object"


def test_default_config_paths_is_global_cline_file() -> None:
    paths = [str(p) for p in ClineAdapter().default_config_paths("Linux", {"HOME": "/home/j"})]
    assert paths == [
        (
            "/home/j/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/"
            "cline_mcp_settings.json"
        )
    ]


def test_no_project_config_paths() -> None:
    # Cline MCP config is global-only — no per-project file.
    assert ClineAdapter().project_config_paths(Path("/proj")) == []
