# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Windsurf host adapter (ADR-4 third adapter)."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.adapters.windsurf import WindsurfAdapter


def test_parses_mcp_servers() -> None:
    raw = json.dumps(
        {"mcpServers": {"svc": {"command": "npx", "args": ["-y", "tool@1.0.0"], "env": {"K": "v"}}}}
    )
    cfg = WindsurfAdapter().parse("/w/mcp_config.json", raw)
    assert cfg.parse_error is None
    assert [s.name for s in cfg.servers] == ["svc"]
    assert cfg.servers[0].command == "npx"
    assert cfg.servers[0].env == (("K", "v"),)
    assert cfg.allow_permissions == ()  # Windsurf has no permission allow-list


def test_never_raises_on_bad_json() -> None:
    cfg = WindsurfAdapter().parse("/w/mcp_config.json", "{nope")
    assert cfg.parse_error is not None
    assert cfg.servers == ()


def test_non_object_root_is_parse_error() -> None:
    cfg = WindsurfAdapter().parse("/w/mcp_config.json", "42")
    assert cfg.parse_error == "config root is not an object"


def test_default_config_paths_is_global_windsurf_file() -> None:
    paths = [str(p) for p in WindsurfAdapter().default_config_paths("Linux", {"HOME": "/home/j"})]
    assert paths == ["/home/j/.codeium/windsurf/mcp_config.json"]


def test_no_project_config_paths() -> None:
    # Windsurf MCP config is global-only — no per-project file.
    assert WindsurfAdapter().project_config_paths(Path("/proj")) == []
