# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Windsurf host adapter (third HostAdapter impl, per ADR-4).

Windsurf (Codeium) stores its MCP servers in a single global config at
``~/.codeium/windsurf/mcp_config.json``, using the same ``mcpServers`` shape as
Claude and Cursor, with no permission allow-list and no per-project config.
Never raises on bad input — malformed JSON becomes a ``ParsedConfig`` with
``parse_error`` set.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePath

from .base import HostAdapter, ParsedConfig, decode_config, parse_mcp_servers
from .paths import windsurf_config_candidates


class WindsurfAdapter(HostAdapter):
    """Adapter for Windsurf MCP config files."""

    name = "windsurf"

    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        return windsurf_config_candidates(system, env)

    def parse(self, path: str, raw: str) -> ParsedConfig:
        data, error = decode_config(raw)
        if error is not None:
            return ParsedConfig(path=path, parse_error=error)

        if not isinstance(data, dict):
            return ParsedConfig(path=path, parse_error="config root is not an object")

        return ParsedConfig(path=path, servers=parse_mcp_servers(data))
