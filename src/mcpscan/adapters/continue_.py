# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Continue host adapter (continue.dev; per ADR-4).

Continue keeps MCP servers in ``config.yaml`` — user-level at
``~/.continue/config.yaml`` and per-workspace at ``<project>/.continue/config.yaml``.
Unlike the JSON hosts, ``mcpServers`` is a **YAML list** (each item carries its
own ``name``), so parsing needs a YAML reader. That reader is the **optional
``[yaml]`` extra** (pyyaml) — the base install stays stdlib-only, and a Continue
config is refused with an install hint when the extra is absent, never crashing.

Never raises: malformed YAML or a missing extra becomes a ``ParsedConfig`` with
``parse_error`` set.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePath

from .base import HostAdapter, ParsedConfig, parse_server_list
from .paths import continue_config_candidates

_YAML_HINT = (
    "Continue configs need the '[yaml]' extra (pip install ianua-broker[yaml]) to be audited"
)


class ContinueAdapter(HostAdapter):
    """Adapter for Continue's ``config.yaml`` MCP servers."""

    name = "continue"

    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        return continue_config_candidates(system, env)

    def project_config_paths(self, project_root: Path) -> list[Path]:
        return [project_root / ".continue" / "config.yaml"]

    def parse(self, path: str, raw: str) -> ParsedConfig:
        try:
            import yaml
        except ImportError:
            return ParsedConfig(path=path, parse_error=_YAML_HINT)

        try:
            data = yaml.safe_load(raw)  # safe_load: never constructs arbitrary objects
        except yaml.YAMLError as exc:
            return ParsedConfig(path=path, parse_error=f"invalid YAML: {exc}")

        if not isinstance(data, dict):
            return ParsedConfig(path=path, parse_error="config root is not a mapping")

        return ParsedConfig(path=path, servers=parse_server_list(data.get("mcpServers")))
