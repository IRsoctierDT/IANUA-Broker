# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Build a normalized :class:`Snapshot` from a scan Report (+ optional Inventory).

Pure and deterministic: the same posture always yields the same facts in the
same order, so a snapshot is byte-stable and its integrity digest is stable.
Secrets never enter a snapshot — a finding contributes only its id/severity/
location fingerprint, never the secret value.
"""

from __future__ import annotations

import hashlib
import json

from ..domain import Report, Server
from ..inventory.model import Inventory
from .model import DRIFT_SCHEMA_VERSION, FactKind, PostureFact, Snapshot


def tool_identity(command: str | None, args: tuple[str, ...], auto_approve: tuple[str, ...]) -> str:
    """A stable, secret-free fingerprint of a declared server's launch identity.

    Hashes ``(command, sorted(args), sorted(auto_approve))`` so the *value* never
    reveals what an arg held — an arg that carries a secret is folded into the
    digest, never stored raw. Two servers with the same command/args/auto-approve
    share an identity; a rug-pull (same name, changed code/tools) changes it,
    which is exactly what :mod:`mcpscan.drift.diff` watches for.
    """
    material = {
        "command": command or "",
        "args": sorted(args),
        "auto_approve": sorted(auto_approve),
    }
    canonical = json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _server_fact(server: Server) -> PostureFact:
    exposure = "exposed" if server.bind_addr and not _is_loopback(server.bind_addr) else "local"
    detail = {
        "state": server.state.value,
        "running": str(server.running).lower(),
        "bind_addr": server.bind_addr or "",
        "port": "" if server.port is None else str(server.port),
        "exposure": exposure,
        # Visibility loss must be diffable: a false→true flip on this key is the
        # silent-failure class of drift (the scanner could no longer see what it
        # saw at baseline time). Older baselines lack the key; diff treats
        # absence as "false".
        "inspection_incomplete": str(server.inspection_incomplete).lower(),
    }
    # Rug-pull fingerprint: present only for config-declared servers (the engine
    # sets it from the ServerDecl). A change on a same-named server is a possible
    # rug-pull. Absent for sockets/process/env servers, and absent from pre-Wave-3
    # baselines — diff treats an absent identity as "unchanged" so an upgrade
    # never manufactures phantom drift.
    if server.tool_identity is not None:
        detail["tool_identity"] = server.tool_identity
    return PostureFact(
        kind=FactKind.SERVER,
        key=f"server:{server.id}",
        summary=server.id,
        detail=_freeze(detail),
    )


def _finding_facts(server: Server) -> list[PostureFact]:
    facts: list[PostureFact] = []
    for finding in server.findings:
        line = "" if finding.location.line is None else str(finding.location.line)
        key = f"finding:{server.id}:{finding.id}:{finding.location.path}:{line}"
        facts.append(
            PostureFact(
                kind=FactKind.FINDING,
                key=key,
                summary=f"{finding.id} — {finding.title}",
                detail=_freeze(
                    {
                        "severity": finding.severity.value,
                        "dimension": finding.dimension.value,
                        "id": finding.id,
                    }
                ),
            )
        )
    return facts


def _asset_facts(inventory: Inventory) -> list[PostureFact]:
    facts: list[PostureFact] = []
    for asset in inventory.assets:
        key = f"asset:{asset.kind.value}:{asset.location}:{asset.server_name or ''}"
        facts.append(
            PostureFact(
                kind=FactKind.ASSET,
                key=key,
                summary=f"{asset.product} ({asset.kind.value})",
                detail=_freeze(
                    {
                        "kind": asset.kind.value,
                        "product": asset.product,
                        "confidence": asset.confidence.value,
                    }
                ),
            )
        )
    return facts


def build_snapshot(report: Report, inventory: Inventory | None = None) -> Snapshot:
    """Normalize a scan Report (and optional Inventory) into a Snapshot."""
    facts: list[PostureFact] = []
    for server in report.servers:
        facts.append(_server_fact(server))
        facts.extend(_finding_facts(server))
    if inventory is not None:
        facts.extend(_asset_facts(inventory))
    facts.sort(key=lambda f: (f.kind.value, f.key))
    return Snapshot(schema_version=DRIFT_SCHEMA_VERSION, facts=tuple(facts))


def snapshot_digest(snapshot: Snapshot) -> str:
    """A stable sha256 over a snapshot's facts (integrity, not a signature).

    Covers the facts only — not any wall-clock metadata — so two snapshots of an
    identical posture share a digest. Detached signing (``ssh-keygen -Y sign``
    over the written file) can wrap this for authenticity when required.
    """
    material = [
        {"kind": f.kind.value, "key": f.key, "detail": dict(f.detail)} for f in snapshot.facts
    ]
    canonical = json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _freeze(detail: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(detail.items()))


def _is_loopback(host: str) -> bool:
    from ..discovery.sockets import is_loopback

    return is_loopback(host)
