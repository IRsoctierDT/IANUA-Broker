# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Renderers for the AI attack-path graph (VISION Tier 3): terminal, JSON, DOT.

Pure functions over the frozen :class:`~mcpscan.graph.model.AttackGraph`. Same
conventions as the ``scan`` / ``trust`` / ``inventory`` renderers:

* **Secretless (R1)** — the graph model carries only env-var KEY NAMEs and
  non-reversible fingerprint handles, so no renderer can emit a raw secret value
  (asserted by the test corpus against a known fake secret in every output).
* **Path privacy (FR-R7)** — node ``detail`` values that carry a filesystem path
  (e.g. an agent host's ``config``) are relativized to ``~`` via
  :func:`~mcpscan.report.display_path`; ``--absolute-paths`` disables that. Node
  *labels* are already path-free (server/host names, key names, provider names).
* **Deterministic** — the builder already sorts nodes and edges, and
  :func:`~mcpscan.graph.paths.analyze_graph` returns paths worst-first, so
  identical inputs render byte-for-byte identical output.

The terminal view answers "show me the attack chains"; the JSON view is the
stable machine surface; the DOT view is the "draw me the graph" affordance
(Graphviz ``digraph``, node shape/colour by kind).
"""

from __future__ import annotations

import json

from ..report import RenderOptions, display_path
from .model import AttackGraph, Node, NodeKind
from .paths import MAX_PATHS

# Node-detail keys whose value is a filesystem path and must be relativized for
# privacy in machine output (labels are already path-free).
_PATH_DETAIL_KEYS = frozenset({"config"})

# Severity-order labels for the terminal header count.
_CRITICAL = "critical"
_HIGH = "high"


def _severity_counts(graph: AttackGraph) -> tuple[int, int]:
    critical = sum(1 for p in graph.paths if p.severity.value == _CRITICAL)
    high = sum(1 for p in graph.paths if p.severity.value == _HIGH)
    return critical, high


def render_terminal_graph(graph: AttackGraph, opts: RenderOptions) -> str:
    """Human-readable attack-path report, most-severe chain first.

    Header names the chain count, the critical/high split, and the overall grade.
    Each chain is a one-line secretless arrow summary tagged with its severity,
    followed by a plain-language ``why``. A graph with no actionable chains says
    so cleanly (the caller exits 0). A capped enumeration is disclosed rather
    than silently under-reported (:attr:`AttackGraph.truncated`).
    """
    del opts  # summaries are path-free; kept for signature symmetry with peers.
    critical, high = _severity_counts(graph)
    lines = [
        (
            f"IANUA-Broker — attack paths: {len(graph.paths)} path(s) "
            f"({critical} critical, {high} high); overall grade {graph.overall_grade}"
        )
    ]

    if not graph.paths:
        lines.append("  No cross-server attack paths found.")
        return "\n".join(lines) + "\n"

    for path in graph.paths:
        lines.append("")
        lines.append(f"[{path.severity.value.upper()}] {path.summary}")
        lines.append(f"    why: {path.rationale}")

    if graph.truncated:
        lines.append("")
        lines.append(
            f"note: results truncated — enumeration hit an exploration cap (chain "
            f"depth or total count); showing the top {min(len(graph.paths), MAX_PATHS)} "
            "ranked chain(s), others were not enumerated."
        )
    return "\n".join(lines) + "\n"


def _detail_dict(node: Node, opts: RenderOptions) -> dict[str, str]:
    """Node ``detail`` as a mapping, relativizing any path-bearing value."""
    return {
        key: (display_path(value, opts) if key in _PATH_DETAIL_KEYS else value)
        for key, value in node.detail
    }


def render_json_graph(graph: AttackGraph, opts: RenderOptions) -> str:
    """Stable, machine-readable graph JSON (sorted keys, deterministic order).

    Emits ``schema_version``, ``overall_grade``, the ``truncated`` cap flag, and
    the ``nodes`` / ``edges`` / ``paths`` collections. Node ids are structural
    identifiers (kept verbatim, as ``trust`` keeps its ``subject``); only
    path-bearing ``detail`` values are relativized. Secretless by construction.
    """
    payload = {
        "schema_version": graph.schema_version,
        "overall_grade": graph.overall_grade,
        "truncated": graph.truncated,
        "nodes": [
            {
                "id": node.id,
                "kind": node.kind.value,
                "label": node.label,
                "detail": _detail_dict(node, opts),
            }
            for node in graph.nodes
        ],
        "edges": [
            {"src": edge.src, "dst": edge.dst, "kind": edge.kind.value, "detail": edge.detail}
            for edge in graph.edges
        ],
        "paths": [
            {
                "nodes": list(path.nodes),
                "edges": [kind.value for kind in path.edges],
                "severity": path.severity.value,
                "summary": path.summary,
                "rationale": path.rationale,
            }
            for path in graph.paths
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# --- DOT export -------------------------------------------------------------
# Graphviz node shape + fill colour per kind. Plain and deterministic; the map is
# total over NodeKind so every node renders with a stable style.
_NODE_STYLE: dict[NodeKind, tuple[str, str]] = {
    NodeKind.ENTRY: ("box", "#ffd7d7"),
    NodeKind.AGENT_HOST: ("box", "#e2e2e2"),
    NodeKind.MCP_SERVER: ("component", "#d7e8ff"),
    NodeKind.CREDENTIAL: ("diamond", "#fff3c4"),
    NodeKind.TARGET: ("octagon", "#ffdca8"),
}


def _dot_escape(text: str) -> str:
    """Escape a string for a double-quoted Graphviz label."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def render_dot_graph(graph: AttackGraph) -> str:
    """Graphviz DOT export of the attack graph — the "draw me the graph" view.

    A directed ``digraph`` laid out left-to-right, one node per line (shape and
    fill colour by kind) then one edge per line labelled with its relationship.
    Deterministic (the builder already sorts nodes and edges) and secretless (ids
    carry a fingerprint handle, labels carry a key name — never a value).
    """
    lines = ["digraph attack_paths {", "  rankdir=LR;", '  node [style=filled, fontname="sans"];']
    for node in graph.nodes:
        shape, fill = _NODE_STYLE[node.kind]
        label = f"{node.kind.value}: {node.label}"
        lines.append(
            f'  "{_dot_escape(node.id)}" '
            f'[label="{_dot_escape(label)}", shape={shape}, fillcolor="{fill}"];'
        )
    for edge in graph.edges:
        lines.append(
            f'  "{_dot_escape(edge.src)}" -> "{_dot_escape(edge.dst)}" '
            f'[label="{_dot_escape(edge.kind.value)}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"
