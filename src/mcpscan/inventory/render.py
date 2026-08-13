# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Inventory renderers: terminal and stable JSON (Tier 1).

Same conventions as the scan renderers: pure functions over the frozen model,
paths relativized to ``~`` via ``RenderOptions``, byte-stable JSON (sorted keys,
deterministic asset order — ``collect`` already sorts).
"""

from __future__ import annotations

import json

from ..report import RenderOptions, display_path
from .model import Asset, AssetKind, AssetSource, Inventory

_KIND_LABELS: dict[AssetKind, str] = {
    AssetKind.AGENT_HOST: "Agent hosts",
    AssetKind.MCP_SERVER: "MCP servers",
    AssetKind.MODEL_SERVER: "Model servers",
    AssetKind.INFERENCE_ENDPOINT: "Inference endpoints",
    AssetKind.LLM_GATEWAY: "LLM gateways",
    AssetKind.VECTOR_DB: "Vector databases",
}


def _location(asset: Asset, opts: RenderOptions) -> str:
    if asset.source is AssetSource.CONFIG:
        return display_path(asset.location, opts)
    return asset.location


def render_terminal_inventory(inventory: Inventory, opts: RenderOptions) -> str:
    """Human-readable inventory, grouped by asset kind."""
    lines = [f"IANUA-Broker — inventory: {len(inventory.assets)} asset(s)"]
    if inventory.inspection_incomplete:
        lines.append("  (inspection incomplete: some processes could not be identified)")

    if not inventory.assets:
        lines.append("  No AI/MCP assets discovered.")
        return "\n".join(lines) + "\n"

    for kind in AssetKind:
        group = [a for a in inventory.assets if a.kind is kind]
        if not group:
            continue
        lines.append("")
        lines.append(f"▶ {_KIND_LABELS[kind]} ({len(group)})")
        for asset in group:
            name = f"{asset.product}"
            if asset.server_name:
                name += f" — '{asset.server_name}'"
            lines.append(f"  {name}  [{asset.confidence.value} confidence]")
            lines.append(f"    where:    {_location(asset, opts)}")
            if asset.proc_name or asset.pid is not None:
                proc = asset.proc_name or "?"
                lines.append(f"    process:  {proc} (pid {asset.pid})")
            lines.append(f"    evidence: {'; '.join(asset.evidence)}")
    return "\n".join(lines) + "\n"


def _asset_to_dict(asset: Asset, opts: RenderOptions) -> dict[str, object]:
    return {
        "kind": asset.kind.value,
        "product": asset.product,
        "source": asset.source.value,
        "location": _location(asset, opts),
        "confidence": asset.confidence.value,
        "evidence": list(asset.evidence),
        "host": asset.host,
        "server_name": asset.server_name,
        "bind_addr": asset.bind_addr,
        "port": asset.port,
        "pid": asset.pid,
        "proc_name": asset.proc_name,
    }


def render_json_inventory(inventory: Inventory, opts: RenderOptions) -> str:
    """Stable, machine-readable inventory JSON."""
    payload = {
        "schema_version": inventory.schema_version,
        "inspection_incomplete": inventory.inspection_incomplete,
        "assets": [_asset_to_dict(a, opts) for a in inventory.assets],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
