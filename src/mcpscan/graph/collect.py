# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Wiring for the AI attack-path graph (VISION Tier 3) — the only I/O layer.

Mirrors :mod:`mcpscan.trust.collect`: it walks the same host-config surfaces as
``engine.scan`` through the adapter seam (read-only, via ``io_safe``), trust-
profiles every declared server, and pairs each secret-bearing env entry's KEY
NAME with its non-reversible fingerprint. It then (optionally) gathers the AI/MCP
inventory, hands everything to the pure :func:`~mcpscan.graph.build.build_graph`,
and returns a fully-analyzed :class:`~mcpscan.graph.model.AttackGraph` via the
pure :func:`~mcpscan.graph.paths.analyze_graph`.

Identity invariants:

* **Read-only** — no writes; reports are the caller's (CLI) business.
* **Offline** — no egress at all. Config reads go through ``io_safe``; the
  inventory is gathered with ``probe=False`` so not even a loopback fingerprint
  socket is opened (only the local listening-socket table is read).
* **Secretless (R1)** — the only credential-derived data that leaves this layer
  is an env-var KEY NAME (e.g. ``GITHUB_TOKEN`` — a name, never a secret) and a
  :class:`~mcpscan.domain.SecretFingerprint`. Detection is delegated to the
  scanner's own predicate (``checks.secrets.check_server_env``); a raw value is
  fingerprinted at detection and never stored.
"""

from __future__ import annotations

import os
import platform
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from ..adapters.base import ServerDecl
from ..checks.secrets import check_server_env
from ..engine import _adapters
from ..inventory.model import Inventory
from ..io_safe import SafeReadError, safe_read_text
from ..trust.analyze import analyze_config
from ..trust.model import TrustProfile
from .build import build_graph
from .model import AttackGraph, CredRef
from .paths import analyze_graph


def _read(path: Path) -> str | None:
    try:
        return safe_read_text(path, root=path.parent)
    except SafeReadError:
        return None


def _credential_refs(server: ServerDecl, config_path: str) -> list[CredRef]:
    """Pair each secret-bearing env KEY of one server with its fingerprint.

    Detection is **not** reimplemented here: the scanner's own predicate
    (:func:`~mcpscan.checks.secrets.check_server_env`) decides which env values
    are secrets. To attach each fingerprint to exactly the KEY that produced it —
    without the fragility of matching fingerprints positionally (two env vars can
    hold a byte-identical value) — the check is run per entry over a single-key
    view of the server, so each detected secret is unambiguously its own key's.
    The raw value is only ever fingerprinted, never stored.
    """
    refs: list[CredRef] = []
    for key, value in server.env:
        one = replace(server, env=((key, value),))
        for finding in check_server_env(one, config_path):
            if finding.secret is not None:
                refs.append(CredRef(env_key=key, fingerprint=finding.secret))
    return refs


def collect_graph(
    *,
    roots: Sequence[Path] | None = None,
    system: str | None = None,
    env: Mapping[str, str] | None = None,
    inventory: bool = True,
) -> AttackGraph:
    """Discover host configs and build the analyzed AI attack-path graph.

    Args:
        roots: Project roots to scan for ``.mcp.json`` / host configs (defaults
            to the current working directory).
        system: ``platform.system()`` override (for deterministic tests).
        env: Environment mapping override (for deterministic tests).
        inventory: When True (default, mirroring ``baseline`` / ``diff``), also
            gather the AI/MCP inventory so non-loopback listening sockets add
            attacker-entry surfaces and declared agent hosts add host nodes. The
            inventory is collected with ``probe=False`` to stay fully offline.

    Returns:
        A fully-analyzed :class:`~mcpscan.graph.model.AttackGraph` with sorted
        nodes/edges, worst-first ``paths``, an ``overall_grade``, and the
        ``truncated`` cap signal set — ready to render.
    """
    system = system or platform.system()
    env = env if env is not None else os.environ
    roots = list(roots) if roots is not None else [Path.cwd()]

    profiles: list[TrustProfile] = []
    secret_holders: dict[str, list[CredRef]] = {}
    for adapter in _adapters():
        candidates = [Path(str(c)) for c in adapter.default_config_paths(system, env)]
        for root in roots:
            candidates.extend(adapter.project_config_paths(root))
        for path in candidates:
            if not path.exists() or not path.is_file():
                continue
            raw = _read(path)
            if raw is None:
                continue
            parsed = adapter.parse(str(path), raw)
            profiles.extend(analyze_config(parsed, adapter.name))
            for server in parsed.servers:
                refs = _credential_refs(server, parsed.path)
                if refs:
                    secret_holders[f"{parsed.path}#{server.name}"] = refs

    inv: Inventory | None = None
    if inventory:
        from ..inventory import collect_inventory

        # probe=False keeps the collection offline: only the local listening-socket
        # table is read, never a fingerprint request to any endpoint.
        inv = collect_inventory(roots=roots, system=system, env=env, probe=False)

    return analyze_graph(build_graph(profiles, inv, secret_holders))
