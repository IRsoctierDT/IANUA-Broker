# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure attack-path enumeration + severity ranking (VISION Tier 3).

Where :mod:`mcpscan.graph.build` produces the *structural* graph (nodes and
edges), this module reasons about **chains**: it walks every ENTRY surface to
every TARGET, keeps only the chains that are genuinely *actionable* (they
traverse a real pivot — a shared credential or a privileged tool, not merely
"reaches a server"), grades each by severity, and grades the whole graph by its
worst chain.

Purity (identity invariant): a **pure function of its inputs** — no I/O, no
clock, no randomness. Enumeration is a bounded depth-first search over simple
paths (no node repeats), and every collection that reaches the output is sorted,
so identical inputs always yield an identical, deterministic result.

Secretless (identity invariant R1): this layer reads only the graph model, whose
credential-derived data is an env-var **key name** and a non-reversible
fingerprint handle — never a value. Summaries and rationales are built from those
share-safe labels alone.

Bounds (documented caps): a chain is at most :data:`MAX_HOPS` edges long, and at
most :data:`MAX_PATHS` chains are returned (the worst-ranked ones). A private
exploration ceiling (:data:`_ENUMERATION_CEILING`) guarantees termination on a
pathologically dense graph. When any cap drops a chain, enumeration is *truncated*
and the flag is surfaced (never silently dropped) via
:attr:`~mcpscan.graph.model.AttackGraph.truncated`, so a renderer can say so.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import replace

from ..domain import Severity
from ..trust.model import TrustFactor
from .model import AttackGraph, AttackPath, Edge, EdgeKind, Node, NodeKind

# --- documented caps --------------------------------------------------------
#: Longest chain enumerated, in edges (hops). The canonical actionable chain
#: (entry -> server -> credential -> peer server -> target) is four hops, so a
#: cap of six leaves head-room for one extra pivot while staying bounded.
MAX_HOPS = 6
#: Most chains returned — the worst-ranked ones survive when this cap bites.
MAX_PATHS = 50
#: Private safety net: stop the DFS after this many actionable chains have been
#: found, so a pathologically dense graph still terminates. Hitting it also marks
#: the result truncated. Comfortably above ``MAX_PATHS`` so ordinary graphs are
#: enumerated in full before any ranking-based truncation.
_ENUMERATION_CEILING = MAX_PATHS * 20

# The two edge kinds that make a chain *actionable* — a real pivot, not mere
# exposure: a credential shared across servers (the cross-server hop) or a
# privileged tool that can act on a target. A chain with neither is exposure the
# ``scan``/``trust`` commands already surface; the graph's value is the chain.
_PIVOT_EDGES = frozenset({EdgeKind.SHARED_WITH, EdgeKind.CAN_ACT})

# Node-detail keys that mark a server as autonomous / privileged. The builder
# writes them as ``f"factor:{factor.value}"`` (see ``build._server_detail``);
# reusing :class:`~mcpscan.trust.model.TrustFactor` keeps a single source of
# truth for the value strings rather than hard-coding them here.
_AUTONOMY_KEY = f"factor:{TrustFactor.AUTONOMY.value}"
_PRIVILEGE_KEY = f"factor:{TrustFactor.TOOL_PRIVILEGE.value}"

# Worst chain severity -> overall graph grade. A small, documented local mapping
# (spec's least-invasive option): a CRITICAL cross-server exfil chain fails the
# graph outright, and an empty graph is a clean "A". Kept deliberately separate
# from the hygiene rubric in ``scoring`` because an attack *chain* is a different
# unit of risk from a per-finding deduction.
_SEVERITY_GRADE: dict[Severity, str] = {
    Severity.CRITICAL: "F",
    Severity.HIGH: "D",
    Severity.MEDIUM: "C",
    Severity.LOW: "B",
    Severity.INFO: "A",
}


def _is_actionable(edge_kinds: Sequence[EdgeKind]) -> bool:
    """True when a chain traverses at least one pivot (SHARED_WITH or CAN_ACT)."""
    return any(kind in _PIVOT_EDGES for kind in edge_kinds)


def _has_key(node: Node, key: str) -> bool:
    return any(k == key for k, _ in node.detail)


def _server_annotation(node: Node) -> str:
    """A parenthetical describing a server's powers, e.g. ``(autonomous, dangerous tools)``."""
    detail = dict(node.detail)
    tags: list[str] = []
    if _AUTONOMY_KEY in detail:
        tags.append("autonomous")
    privilege = detail.get(_PRIVILEGE_KEY)
    if privilege is not None:
        tags.append("dangerous tools" if "dangerous" in privilege else "privileged")
    return f" ({', '.join(tags)})" if tags else ""


def _entry_reach(path_nodes: Sequence[str], node_by_id: dict[str, Node]) -> str:
    """The ``reach`` detail of the chain's ENTRY surface, lowercased (``""`` if none)."""
    for nid in path_nodes:
        node = node_by_id.get(nid)
        if node is not None and node.kind is NodeKind.ENTRY:
            return dict(node.detail).get("reach", "").lower()
    return ""


def _path_severity(
    path_nodes: Sequence[str],
    path_edges: Sequence[EdgeKind],
    node_by_id: dict[str, Node],
) -> Severity:
    """Rank one actionable chain by how reachable its entry surface is.

    Actionability (an autonomous/privileged CAN_ACT or a shared-credential pivot)
    is what makes the chain *exist* — enumeration already requires it. What
    *varies*, and therefore sets severity, is how exposed the way in is:

    - CRITICAL: the entry is a wildcard / public-routable bind (remotely
      triggerable) **or** the chain crosses a shared credential (a cross-server
      blast radius that widens the compromise regardless of where it starts).
    - HIGH: the entry is a private-LAN bind — reachable by anything on the LAN.
    - MEDIUM: no network-reachable entry — the chain needs a prior local
      foothold before it can be walked.

    (In this trust model a server's privilege and autonomy both derive from its
    auto-approve list, so "privileged but human-gated" does not occur; grading on
    the entry's reach is the axis that genuinely distinguishes chains.)
    """
    if EdgeKind.SHARED_WITH in path_edges:
        return Severity.CRITICAL
    reach = _entry_reach(path_nodes, node_by_id)
    if "wildcard" in reach or "public" in reach:
        return Severity.CRITICAL
    if "private" in reach or "lan" in reach:
        return Severity.HIGH
    return Severity.MEDIUM


def _summarize(
    path_nodes: Sequence[str],
    path_edges: Sequence[EdgeKind],
    node_by_id: dict[str, Node],
) -> str:
    """Build a secretless one-line arrow chain from an entry to a target.

    e.g. ``exposed 'db' (wildcard / public bind) -> shared credential GITHUB_TOKEN
    -> 'shell' (autonomous, dangerous tools) -> GitHub``. The exposed entry and
    the server that shares its surface (same label) are collapsed into one
    segment so the chain reads once, not twice.
    """
    segments: list[str] = []
    i, n = 0, len(path_nodes)
    while i < n:
        node = node_by_id[path_nodes[i]]
        if node.kind is NodeKind.ENTRY:
            reach = dict(node.detail).get("reach", "")
            segment = f"exposed '{node.label}'"
            if reach:
                segment += f" ({reach} bind)"
            segments.append(segment)
            # Collapse the immediately-reached server that shares this surface.
            if i + 1 < n:
                nxt = node_by_id[path_nodes[i + 1]]
                if nxt.kind is NodeKind.MCP_SERVER and nxt.label == node.label:
                    i += 2
                    continue
        elif node.kind is NodeKind.MCP_SERVER:
            segments.append(f"'{node.label}'{_server_annotation(node)}")
        elif node.kind is NodeKind.CREDENTIAL:
            out_edge = path_edges[i] if i < len(path_edges) else None
            prefix = "shared credential" if out_edge is EdgeKind.SHARED_WITH else "credential"
            segments.append(f"{prefix} {node.label}")
        else:  # NodeKind.TARGET
            segments.append(node.label)
        i += 1
    return " -> ".join(segments)


def _rationale(
    path_nodes: Sequence[str],
    path_edges: Sequence[EdgeKind],
    node_by_id: dict[str, Node],
    severity: Severity,
) -> str:
    """Explain, in plain language, why the chain is actionable at its severity."""
    target_label = node_by_id[path_nodes[-1]].label
    reasons: list[str] = []
    if EdgeKind.SHARED_WITH in path_edges:
        reasons.append(
            "a credential shared across servers lets the attacker pivot from the "
            "exposed server to another that holds the same secret"
        )
    if path_edges and path_edges[-1] is EdgeKind.CAN_ACT:
        acting = node_by_id.get(path_nodes[-2])
        if acting is not None and _has_key(acting, _AUTONOMY_KEY):
            reasons.append(
                f"'{acting.label}' auto-approves dangerous/wildcard tools, so it acts "
                "on the target with no human in the loop"
            )
        elif acting is not None and _has_key(acting, _PRIVILEGE_KEY):
            reasons.append(
                f"'{acting.label}' wields dangerous/wildcard tools (behind a human "
                "approval gate) to act on the target"
            )
    if not reasons:
        reasons.append("a privileged tool can act on the target")
    return f"Chain from an exposed surface to {target_label}: " + "; ".join(reasons) + "."


def _make_path(
    path_nodes: Sequence[str],
    path_edges: Sequence[EdgeKind],
    node_by_id: dict[str, Node],
) -> AttackPath:
    severity = _path_severity(path_nodes, path_edges, node_by_id)
    return AttackPath(
        nodes=tuple(path_nodes),
        edges=tuple(path_edges),
        severity=severity,
        summary=_summarize(path_nodes, path_edges, node_by_id),
        rationale=_rationale(path_nodes, path_edges, node_by_id, severity),
    )


def _rank_key(path: AttackPath) -> tuple[int, int, tuple[str, ...]]:
    """Deterministic worst-first ordering: severity desc, hops asc, then node ids.

    Mirrors :attr:`AttackGraph.critical_paths` so enumeration and that property
    agree on ordering.
    """
    return (-path.severity.weight, len(path.nodes), path.nodes)


def _adjacency(edges: Sequence[Edge]) -> dict[str, list[tuple[EdgeKind, str]]]:
    """Deduplicated, deterministically-ordered successor map for the DFS.

    Two edges with the same ``(src, dst, kind)`` but different ``detail`` collapse
    to one successor so a chain is never enumerated twice.
    """
    seen: dict[str, set[tuple[EdgeKind, str]]] = defaultdict(set)
    for edge in edges:
        seen[edge.src].add((edge.kind, edge.dst))
    return {src: sorted(succ, key=lambda kd: (kd[0].value, kd[1])) for src, succ in seen.items()}


def _enumerate(nodes: Sequence[Node], edges: Sequence[Edge]) -> tuple[tuple[AttackPath, ...], bool]:
    """Enumerate actionable chains and report whether a cap truncated the result.

    Returns the worst-first, capped chains and a ``truncated`` flag (set when the
    exploration ceiling was hit or the ranked result exceeded :data:`MAX_PATHS`).
    """
    node_by_id = {n.id: n for n in nodes}
    adjacency = _adjacency(edges)
    entries = sorted(n.id for n in nodes if n.kind is NodeKind.ENTRY)

    found: list[AttackPath] = []
    ceiling_hit = False
    depth_capped = False

    def visit(
        current: str, visited: set[str], nodes_acc: list[str], edges_acc: list[EdgeKind]
    ) -> None:
        nonlocal ceiling_hit, depth_capped
        if ceiling_hit:
            return
        node = node_by_id[current]
        # A target is a sink: record the chain (if actionable) and stop — never
        # walk past it.
        if node.kind is NodeKind.TARGET:
            if len(nodes_acc) > 1 and _is_actionable(edges_acc):
                if len(found) >= _ENUMERATION_CEILING:
                    ceiling_hit = True
                    return
                found.append(_make_path(nodes_acc, edges_acc, node_by_id))
            return
        if len(edges_acc) >= MAX_HOPS:
            # Stopping at the depth cap with edges still ahead means a longer
            # chain may exist that we did not explore — disclose the truncation
            # rather than drop it silently.
            if any(dst not in visited for _, dst in adjacency.get(current, ())):
                depth_capped = True
            return
        for kind, dst in adjacency.get(current, ()):
            if dst in visited:
                continue
            visited.add(dst)
            nodes_acc.append(dst)
            edges_acc.append(kind)
            visit(dst, visited, nodes_acc, edges_acc)
            edges_acc.pop()
            nodes_acc.pop()
            visited.discard(dst)
            if ceiling_hit:
                return

    for entry in entries:
        visit(entry, {entry}, [entry], [])

    found.sort(key=_rank_key)
    truncated = ceiling_hit or depth_capped or len(found) > MAX_PATHS
    return tuple(found[:MAX_PATHS]), truncated


def enumerate_paths(nodes: Sequence[Node], edges: Sequence[Edge]) -> tuple[AttackPath, ...]:
    """Enumerate the actionable attacker chains from ENTRY surfaces to TARGETs.

    A bounded, deterministic depth-first search over simple paths (see the module
    docstring for the caps). Only *actionable* chains — those that traverse a
    shared-credential or privileged-tool pivot — are returned, worst-ranked first
    (severity desc, then fewest hops, then node ids). The chains are capped at
    :data:`MAX_PATHS`; use :func:`analyze_graph` when you also need the truncation
    signal and the overall grade.
    """
    paths, _truncated = _enumerate(nodes, edges)
    return paths


def overall_grade_for_paths(paths: Sequence[AttackPath]) -> str:
    """Grade a graph from its worst enumerated chain (``"A"`` when there are none)."""
    if not paths:
        return "A"
    worst = max(paths, key=lambda p: p.severity.weight)
    return _SEVERITY_GRADE[worst.severity]


def analyze_graph(graph: AttackGraph) -> AttackGraph:
    """Return a copy of ``graph`` with chains enumerated, graded, and cap-flagged.

    The convenience entry point over :func:`enumerate_paths`: it runs the
    bounded DFS once, sets :attr:`~mcpscan.graph.model.AttackGraph.paths`, derives
    :attr:`~mcpscan.graph.model.AttackGraph.overall_grade` from the worst chain,
    and records :attr:`~mcpscan.graph.model.AttackGraph.truncated` so a renderer
    can disclose a capped result. Pure over the structural graph the builder
    returns; the input graph is left unchanged (it is frozen and rebuilt via
    :func:`dataclasses.replace`).
    """
    paths, truncated = _enumerate(graph.nodes, graph.edges)
    return replace(
        graph,
        paths=paths,
        overall_grade=overall_grade_for_paths(paths),
        truncated=truncated,
    )
