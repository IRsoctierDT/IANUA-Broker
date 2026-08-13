# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""AI attack-path graph (VISION Tier 3): tool- and trust-chaining analysis.

Where ``scan`` grades hygiene, ``inventory`` names what exists, and ``trust``
scores a single tool, this package reasons about **chaining** — how an attacker
on an exposed surface pivots, via shared credentials and privileged/autonomous
tools, to a high-value target. It is a pure graph over data the tool already
collects (plus one safe inference: a credential key name -> the target it
unlocks). No new I/O, no egress, secretless, deterministic.
"""

from .build import build_graph, infer_target
from .collect import collect_graph
from .model import (
    GRAPH_SCHEMA_VERSION,
    AttackGraph,
    AttackPath,
    CredRef,
    Edge,
    EdgeKind,
    Node,
    NodeKind,
)
from .paths import (
    MAX_HOPS,
    MAX_PATHS,
    analyze_graph,
    enumerate_paths,
    overall_grade_for_paths,
)
from .render import render_dot_graph, render_json_graph, render_terminal_graph

__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "MAX_HOPS",
    "MAX_PATHS",
    "AttackGraph",
    "AttackPath",
    "CredRef",
    "Edge",
    "EdgeKind",
    "Node",
    "NodeKind",
    "analyze_graph",
    "build_graph",
    "collect_graph",
    "enumerate_paths",
    "infer_target",
    "overall_grade_for_paths",
    "render_dot_graph",
    "render_json_graph",
    "render_terminal_graph",
]
