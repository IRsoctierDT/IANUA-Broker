# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Claude-ecosystem host adapter (ticket T-205, first HostAdapter impl).

Parses the ``mcpServers`` mapping and permission allow-lists from Claude Code
settings, project ``.mcp.json``, and Claude Desktop config. Never raises on bad
input — malformed JSON becomes a ``ParsedConfig`` with ``parse_error`` set.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path, PurePath

from .base import (
    HostAdapter,
    ParsedConfig,
    coerce_str_list,
    parse_mcp_servers,
)
from .paths import (
    claude_config_candidates,
    claude_credential_candidates,
    claude_telemetry_candidates,
)


class ClaudeAdapter(HostAdapter):
    """Adapter for Claude Code / Claude Desktop config files."""

    name = "claude"

    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        return claude_config_candidates(system, env)

    def project_config_paths(self, project_root: Path) -> list[Path]:
        return [project_root / ".mcp.json"]

    def credential_artifact_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        # Claude Code's ``~/.claude/.credentials.json`` OAuth token store.
        return claude_credential_candidates(system, env)

    def telemetry_surfaces(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        # Claude Desktop's per-OS agent/MCP log directory (Feature L registry seam).
        return claude_telemetry_candidates(system, env)

    def parse(self, path: str, raw: str) -> ParsedConfig:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            return ParsedConfig(path=path, parse_error=f"invalid JSON: {exc}")

        if not isinstance(data, dict):
            return ParsedConfig(path=path, parse_error="config root is not an object")

        allow: tuple[str, ...] = ()
        permissions = data.get("permissions")
        if isinstance(permissions, dict):
            allow = coerce_str_list(permissions.get("allow"))

        return ParsedConfig(
            path=path,
            servers=parse_mcp_servers(data),
            allow_permissions=allow,
        )
