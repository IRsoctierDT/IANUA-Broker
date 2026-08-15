# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""VS Code host adapter (native MCP support, per ADR-4).

VS Code stores MCP servers in ``mcp.json`` — per-workspace at
``<project>/.vscode/mcp.json`` and user-level under the editor's ``User`` profile
directory. Unlike the Claude-lineage hosts it uses a top-level ``servers`` key
(not ``mcpServers``); the per-server spec (``command``/``args``/``env``) is the
same, so parsing reuses the shared helper via ``parse_named_servers``. For
tolerance the adapter also accepts a ``mcpServers`` key if present. Never raises
on bad input — malformed JSON becomes a ``ParsedConfig`` with ``parse_error``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePath

from .base import HostAdapter, ParsedConfig, decode_config, parse_named_servers
from .jsonc import loads_jsonc
from .paths import vscode_config_candidates


class VSCodeAdapter(HostAdapter):
    """Adapter for VS Code MCP config files (``mcp.json``)."""

    name = "vscode"

    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        return vscode_config_candidates(system, env)

    def project_config_paths(self, project_root: Path) -> list[Path]:
        return [project_root / ".vscode" / "mcp.json"]

    def parse(self, path: str, raw: str) -> ParsedConfig:
        # mcp.json is JSONC (VS Code allows comments + trailing commas).
        data, error = decode_config(raw, loader=loads_jsonc)
        if error is not None:
            return ParsedConfig(path=path, parse_error=error)

        if not isinstance(data, dict):
            return ParsedConfig(path=path, parse_error="config root is not an object")

        # VS Code uses "servers"; accept "mcpServers" too for forward tolerance.
        servers = parse_named_servers(data, "servers") or parse_named_servers(data, "mcpServers")
        return ParsedConfig(path=path, servers=servers)
