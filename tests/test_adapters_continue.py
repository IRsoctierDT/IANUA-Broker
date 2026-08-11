# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Continue host adapter (ADR-4; YAML config, [yaml] extra)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcpscan.adapters.continue_ import ContinueAdapter

_CONFIG = """
name: My Config
version: 1.0.0
schema: v1
mcpServers:
  - name: db
    command: npx
    args: ["-y", "db-mcp-server"]
    env:
      POSTGRES_PASSWORD: S3cr3t-Pa55w0rd-abcdef123456
  - command: node      # no explicit name -> positional fallback
    args: ["s.js"]
"""


def test_parses_yaml_mcpservers_list() -> None:
    cfg = ContinueAdapter().parse("/c/.continue/config.yaml", _CONFIG)
    assert cfg.parse_error is None
    names = [s.name for s in cfg.servers]
    assert names == ["db", "server-1"]  # second server gets the positional name
    assert cfg.servers[0].command == "npx"
    assert cfg.servers[0].env == (("POSTGRES_PASSWORD", "S3cr3t-Pa55w0rd-abcdef123456"),)
    assert cfg.allow_permissions == ()


def test_invalid_yaml_is_parse_error() -> None:
    cfg = ContinueAdapter().parse("/c/.continue/config.yaml", "mcpServers: [unclosed")
    assert cfg.parse_error is not None
    assert cfg.servers == ()


def test_non_mapping_root_is_parse_error() -> None:
    cfg = ContinueAdapter().parse("/c/.continue/config.yaml", "- just\n- a\n- list\n")
    assert cfg.parse_error == "config root is not a mapping"


def test_non_dict_server_entry_is_skipped() -> None:
    raw = 'mcpServers:\n  - name: ok\n    command: node\n  - "just a string"\n'
    cfg = ContinueAdapter().parse("/c/.continue/config.yaml", raw)
    assert cfg.parse_error is None
    assert [s.name for s in cfg.servers] == ["ok"]  # the scalar entry is ignored


def test_config_without_mcpservers_is_silent() -> None:
    # A valid Continue config with no MCP servers must be silent, not an error.
    cfg = ContinueAdapter().parse("/c/.continue/config.yaml", "name: cfg\nmodels: []\n")
    assert cfg.parse_error is None and cfg.servers == ()


def test_missing_yaml_extra_is_reported_not_crashed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate the [yaml] extra being absent: the yaml import fails.
    monkeypatch.setitem(sys.modules, "yaml", None)
    cfg = ContinueAdapter().parse("/c/.continue/config.yaml", _CONFIG)
    assert cfg.parse_error is not None and "yaml" in cfg.parse_error
    assert cfg.servers == ()


def test_default_config_paths_is_dot_continue() -> None:
    paths = [str(p) for p in ContinueAdapter().default_config_paths("Linux", {"HOME": "/home/j"})]
    assert paths == ["/home/j/.continue/config.yaml"]


def test_project_config_path_is_dot_continue() -> None:
    assert ContinueAdapter().project_config_paths(Path("/proj")) == [
        Path("/proj/.continue/config.yaml")
    ]
