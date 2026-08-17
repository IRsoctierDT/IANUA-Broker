# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Zed host adapter (native MCP support, per ADR-4).

Zed declares MCP servers under a top-level ``context_servers`` map in its
``settings.json`` — user-level at ``~/.config/zed/settings.json`` (macOS + Linux)
and per-workspace at ``<project>/.zed/settings.json``. The per-server spec is
flat (``command``/``args``/``env``), like the Claude-lineage hosts, so parsing
reuses the shared helper; a server with a ``url`` instead of a ``command`` is a
remote endpoint and parses with ``command=None``.

Zed settings are **JSONC** (comments + trailing commas), so parsing goes through
``loads_jsonc``. Never raises on bad input — malformed content becomes a
``ParsedConfig`` with ``parse_error`` set.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePath

from .base import HostAdapter, ParsedConfig, decode_config, parse_named_servers
from .jsonc import loads_jsonc
from .paths import zed_config_candidates


class ZedAdapter(HostAdapter):
    """Adapter for Zed MCP config (``context_servers`` in ``settings.json``)."""

    name = "zed"

    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        return zed_config_candidates(system, env)

    def project_config_paths(self, project_root: Path) -> list[Path]:
        return [project_root / ".zed" / "settings.json"]

    def parse(self, path: str, raw: str) -> ParsedConfig:
        data, error = decode_config(raw, loader=loads_jsonc)
        if error is not None:
            return ParsedConfig(path=path, parse_error=error)

        if not isinstance(data, dict):
            return ParsedConfig(path=path, parse_error="config root is not an object")

        return ParsedConfig(path=path, servers=parse_named_servers(data, "context_servers"))
