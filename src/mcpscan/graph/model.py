# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure model for the AI attack-path graph (VISION Tier 3).

Where ``scan`` grades hygiene, ``inventory`` names what exists, and ``trust``
scores what a single tool is trusted with, the attack-path graph reasons about
**chaining**: how an attacker who lands on an exposed surface pivots — via shared
credentials and privileged, autonomous tools — to a high-value target. The
canonical chain is ``Laptop -> model runtime -> MCP server -> filesystem tool ->
GitHub token -> private repo``.

This module is **frozen, enum-driven, and contains no I/O**. Like the rest of the
model layer it is deterministic and unit-testable without a filesystem or
network.

Secretless by construction (identity invariant R1): a :class:`CredRef` and a
:class:`Node` of kind :attr:`NodeKind.CREDENTIAL` carry only an env-var **key
name** (e.g. ``GITHUB_TOKEN`` — a name, never a value) and a non-reversible
:class:`~mcpscan.domain.SecretFingerprint`. A raw secret value is never present
on any type here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..domain import SecretFingerprint, Severity

GRAPH_SCHEMA_VERSION = "1.0"


class NodeKind(Enum):
    """What a node in the attack-path graph represents."""

    ENTRY = "entry"  # an attacker entry — an exposed / network-reachable surface
    AGENT_HOST = "agent_host"  # an agent/IDE host whose config declared a server
    MCP_SERVER = "mcp_server"  # a declared MCP server (the agent's tool provider)
    CREDENTIAL = "credential"  # a credential a server holds (keyed by fingerprint)
    TARGET = "target"  # what a credential unlocks (GitHub, AWS, a database, …)


class EdgeKind(Enum):
    """A directed relationship between two nodes."""

    HOSTS = "hosts"  # agent host -> the server it declares
    REACHES = "reaches"  # entry surface -> the server it exposes
    HOLDS = "holds"  # server -> a credential in its environment
    SHARED_WITH = "shared_with"  # credential -> each server that also holds it (the pivot)
    UNLOCKS = "unlocks"  # credential -> the target it grants access to
    CAN_ACT = "can_act"  # server -> a target it can act on via a privileged tool


@dataclass(frozen=True)
class CredRef:
    """A secretless reference to one credential a server holds.

    Carries the environment-variable **key name** (``env_key`` — e.g.
    ``GITHUB_TOKEN``, which is a name, not a secret) and the value's
    non-reversible :class:`~mcpscan.domain.SecretFingerprint`. The raw value is
    never stored. Two references name the *same* credential when their
    fingerprints share ``(sha256_8, length)``.
    """

    env_key: str
    fingerprint: SecretFingerprint


@dataclass(frozen=True)
class Node:
    """One node in the attack-path graph.

    ``id`` is stable and content-addressed by kind (``server:<subject>``,
    ``cred:<sha256_8>:<len>``, ``target:github``, ``host:<path>``,
    ``entry:<subject>``); ``detail`` is a tuple of sorted ``(key, value)`` facts
    (reach tier, grade, factor summaries) and is secretless.
    """

    id: str
    kind: NodeKind
    label: str
    detail: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Edge:
    """A directed edge from ``src`` to ``dst`` node id, annotated with a reason."""

    src: str
    dst: str
    kind: EdgeKind
    detail: str = ""


@dataclass(frozen=True)
class AttackPath:
    """One enumerated attacker chain from an ENTRY to a TARGET.

    ``nodes`` is the ordered node-id sequence (entry -> … -> target); ``edges``
    is the parallel sequence of edge kinds traversed between them. ``severity``
    reuses :class:`~mcpscan.domain.Severity`. ``summary`` is a human one-liner
    and ``rationale`` explains why the chain is actionable.
    """

    nodes: tuple[str, ...]
    edges: tuple[EdgeKind, ...]
    severity: Severity
    summary: str
    rationale: str


@dataclass(frozen=True)
class AttackGraph:
    """The full attack-path graph: nodes, edges, enumerated paths, and a grade.

    :func:`~mcpscan.graph.build.build_graph` returns the *structural* graph
    (nodes and edges) with ``paths`` empty and ``overall_grade`` at its best
    ``"A"`` — path enumeration and grading are a separate, equally pure step
    (``graph.paths``) so the builder stays purely about structure.

    ``truncated`` is the documented-cap signal: :func:`~mcpscan.graph.paths.analyze_graph`
    sets it ``True`` when path enumeration hit its depth/count caps and dropped
    paths, so a renderer can say so rather than silently under-reporting.
    """

    schema_version: str
    nodes: tuple[Node, ...] = ()
    edges: tuple[Edge, ...] = ()
    paths: tuple[AttackPath, ...] = field(default_factory=tuple)
    overall_grade: str = "A"
    truncated: bool = False

    @property
    def critical_paths(self) -> tuple[AttackPath, ...]:
        """CRITICAL/HIGH paths, worst first (weight desc, then hops asc, then ids)."""
        severe = [p for p in self.paths if p.severity in (Severity.CRITICAL, Severity.HIGH)]
        return tuple(sorted(severe, key=lambda p: (-p.severity.weight, len(p.nodes), p.nodes)))
