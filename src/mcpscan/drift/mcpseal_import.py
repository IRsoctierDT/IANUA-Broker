# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Import an mcpseal ``.mcp-lock.json`` as drift-baseline pins (R-LIVE-TOOL-DRIFT).

mcpseal pins each approved tool as ``sha256`` over canonical
``{name, description, inputSchema}``. Importing turns those pins into tool
facts in an mcpscan baseline, so ``mcpscan diff`` gates the same rug pulls an
existing mcpseal user already approved against, while adding everything else
mcpscan checks (findings, exposure, signed baselines, the acceptance ledger).

Mapping: an mcpseal server named ``NAME`` becomes ``stdio://NAME`` — the id a
``--spawn-stdio NAME=IMAGE@sha256:…`` inspection produces, so run ``diff`` with
the same names. Only ``approved`` tools are pinned; ``denied``/``quarantined``
entries are skipped with a warning.

The lockfile is **untrusted input**: bounded size and depth, strict types, a
known ``version`` only (fail closed on anything newer), allowlisted server
names, and digest format checks. mcpseal stores the last-approved description
in **plaintext**; this importer never reads it into the baseline — only the
digest crosses over. Imported facts are marked ``provenance: mcpseal-import``
so ``diff`` compares only what the lockfile can vouch for.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..discovery.live_tools import MAX_JSON_DEPTH, MAX_NAME_CHARS, MAX_TOOLS
from ..discovery.stdio_sandbox import valid_server_name
from .model import FactKind, PostureFact

SUPPORTED_VERSIONS: frozenset[int] = frozenset({1})
MAX_LOCKFILE_BYTES = 4 * 1024 * 1024
MAX_SERVERS = 200
PROVENANCE = "mcpseal-import"
_HASH_RE = re.compile(r"sha256:([0-9a-f]{64})")


class LockfileImportError(ValueError):
    """The lockfile was refused as a whole (messages never quote its contents)."""


@dataclass(frozen=True)
class LockImport:
    """Facts imported from one lockfile, plus per-entry warnings."""

    facts: tuple[PostureFact, ...]
    warnings: tuple[str, ...]


def _depth_ok(text: str) -> bool:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif char in "]}":
            depth -= 1
    return True


def _server_fact(server_id: str) -> PostureFact:
    """The SERVER fact a successful ``--spawn-stdio`` inspection of this server produces."""
    detail = {
        "state": "running",
        "running": "true",
        "bind_addr": "",
        "port": "",
        "exposure": "local",
        "inspection_incomplete": "false",
    }
    return PostureFact(
        kind=FactKind.SERVER,
        key=f"server:{server_id}",
        summary=server_id,
        detail=tuple(sorted(detail.items())),
    )


def _valid_tool_name(name: object) -> bool:
    return (
        isinstance(name, str)
        and 0 < len(name) <= MAX_NAME_CHARS
        and all(0x20 <= ord(c) != 0x7F for c in name)
    )


def parse_mcp_lock(text: str) -> LockImport:
    """Parse an mcpseal lockfile into baseline facts (pure).

    Raises:
        LockfileImportError: the document is not an mcpseal lockfile this
            version understands (refused whole — never partially trusted).
    """
    if len(text.encode("utf-8")) > MAX_LOCKFILE_BYTES:
        raise LockfileImportError("lockfile is larger than 4 MiB")
    if not _depth_ok(text):
        raise LockfileImportError("lockfile nesting is too deep")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise LockfileImportError("lockfile is not valid JSON") from exc
    if not isinstance(data, dict):
        raise LockfileImportError("lockfile is not a JSON object")
    version = data.get("version")
    if type(version) is not int or version not in SUPPORTED_VERSIONS:
        raise LockfileImportError(
            "unsupported lockfile version (supported: 1); refusing rather than guessing"
        )
    servers = data.get("servers")
    if not isinstance(servers, dict) or len(servers) > MAX_SERVERS:
        raise LockfileImportError("lockfile 'servers' is missing or too large")

    facts: list[PostureFact] = []
    warnings: list[str] = []
    for name in sorted(servers):
        entry = servers[name]
        if not valid_server_name(name):
            warnings.append(
                f"skipped a server whose name is not a valid --spawn-stdio name ({name!r:.40})"
            )
            continue
        tools = entry.get("tools") if isinstance(entry, dict) else None
        if not isinstance(tools, dict) or len(tools) > MAX_TOOLS:
            warnings.append(f"skipped server {name!r}: 'tools' is missing or too large")
            continue
        server_id = f"stdio://{name}"
        pinned = 0
        for tool_name in sorted(tools):
            tool = tools[tool_name]
            if not _valid_tool_name(tool_name) or not isinstance(tool, dict):
                warnings.append(f"skipped a malformed tool entry on server {name!r}")
                continue
            if tool.get("status") != "approved":
                warnings.append(f"not pinning {name}:{tool_name!r:.80} (status is not 'approved')")
                continue
            match = _HASH_RE.fullmatch(str(tool.get("hash", "")))
            if match is None:
                warnings.append(f"skipped {name}:{tool_name!r:.80}: hash is not sha256:<64 hex>")
                continue
            detail = {"server": server_id, "mcpseal": match.group(1), "provenance": PROVENANCE}
            facts.append(
                PostureFact(
                    kind=FactKind.TOOL,
                    key=f"tool:{server_id}:{tool_name}",
                    summary=f"{server_id} tool {tool_name!r}",
                    detail=tuple(sorted(detail.items())),
                )
            )
            pinned += 1
        if pinned:
            facts.append(_server_fact(server_id))
    return LockImport(facts=tuple(facts), warnings=tuple(warnings))
