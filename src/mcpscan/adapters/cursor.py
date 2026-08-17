# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Cursor host adapter (second HostAdapter impl, per ADR-4).

Cursor stores its MCP servers in ``mcp.json`` — globally at ``~/.cursor/mcp.json``
and per-project at ``<root>/.cursor/mcp.json`` — using the same ``mcpServers``
shape as Claude. Cursor has no permission allow-list, so only servers are parsed.
Never raises on bad input — malformed JSON becomes a ``ParsedConfig`` with
``parse_error`` set.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePath

from .base import HostAdapter, ParsedConfig, decode_config, parse_mcp_servers
from .paths import cursor_config_candidates


class CursorAdapter(HostAdapter):
    """Adapter for Cursor MCP config files."""

    name = "cursor"

    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        return cursor_config_candidates(system, env)

    def project_config_paths(self, project_root: Path) -> list[Path]:
        return [project_root / ".cursor" / "mcp.json"]

    def parse(self, path: str, raw: str) -> ParsedConfig:
        data, error = decode_config(raw)
        if error is not None:
            return ParsedConfig(path=path, parse_error=error)

        if not isinstance(data, dict):
            return ParsedConfig(path=path, parse_error="config root is not an object")

        return ParsedConfig(path=path, servers=parse_mcp_servers(data))
