# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure construction of the AI attack-path graph (VISION Tier 3).

:func:`build_graph` turns data the scanner already collects — trust profiles
(Tier 4), the AI/MCP inventory (Tier 1), and per-server credential references —
into the *structural* graph (nodes and edges). It is a **pure function of its
inputs**: no I/O, no clock, no randomness, and every collection that reaches the
output is sorted, so identical inputs always yield an identical graph.

Path enumeration and grading are a separate step (:mod:`mcpscan.graph.paths`),
so this module stays purely about structure.

Secretless (identity invariant R1): the only credential-derived data that enters
a node is an env-var **key name** (e.g. ``GITHUB_TOKEN`` — a name, not a secret)
and a non-reversible :class:`~mcpscan.domain.SecretFingerprint`. A raw secret
value is never read here — it never reaches this layer to begin with.

One new *safe* inference lives here: :func:`infer_target` maps a credential key
name to the target it unlocks, using a small, conservative, documented catalog
(a future signed data-pack candidate). It reasons only over the KEY NAME.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence

from ..discovery.sockets import ReachTier, classify_reachability
from ..inventory.model import AssetKind, AssetSource, Inventory
from ..trust.model import TrustFactor, TrustProfile
from .model import (
    GRAPH_SCHEMA_VERSION,
    AttackGraph,
    CredRef,
    Edge,
    EdgeKind,
    Node,
    NodeKind,
)

# --- target inference -------------------------------------------------------
# Conservative, case-insensitive substring catalog: credential KEY NAME -> the
# target it unlocks. Order matters — the first matching group wins, so more
# specific provider names are listed before the generic ``API_KEY`` fallback
# (e.g. ``GITHUB_API_KEY`` resolves to GitHub, not the generic LLM provider).
# Deliberately small and documented; a future signed data-pack candidate.
_TARGET_CATALOG: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("GITHUB", "GH_TOKEN"), "github", "GitHub"),
    (("AWS",), "aws", "AWS"),
    (("GCP", "GOOGLE"), "gcp", "Google Cloud"),
    (("AZURE",), "azure", "Azure"),
    (("SLACK",), "slack", "Slack"),
    (("POSTGRES", "MYSQL", "DATABASE_URL", "DB_PASS"), "database", "Database"),
    (("OPENAI", "ANTHROPIC", "API_KEY"), "llm_provider", "LLM provider API"),
    (("NPM", "PYPI", "REGISTRY"), "package_registry", "Package registry"),
)

# The synthetic TARGET a server "can act on" directly when it auto-approves a
# dangerous exec/shell/filesystem tool — no credential required, the tool itself
# is the reach into the local machine.
_LOCAL_SHELL_ID = "local_shell"
_LOCAL_SHELL_LABEL = "Local filesystem / shell"


def infer_target(env_key: str) -> tuple[str, str] | None:
    """Map a credential's env-var key name to ``(target_id, label)`` it unlocks.

    Case-insensitive substring match against the built-in :data:`_TARGET_CATALOG`;
    the first matching group wins. Returns ``None`` for an unknown key (the
    credential is still a node, it just unlocks no known target). Pure and
    secretless — reasons only over the KEY NAME, never a value.
    """
    upper = env_key.upper()
    for needles, target_id, label in _TARGET_CATALOG:
        if any(needle in upper for needle in needles):
            return target_id, label
    return None


# --- profile-derived predicates (secretless, pure over the profile) ---------
def _present(profile: TrustProfile, factor: TrustFactor) -> bool:
    return any(f.factor is factor and f.present for f in profile.factors)


def _factor_detail(profile: TrustProfile, factor: TrustFactor) -> str:
    return next((f.detail for f in profile.factors if f.factor is factor and f.present), "")


def _has_dangerous_tools(profile: TrustProfile) -> bool:
    """True when the server auto-approves a dangerous exec/shell/filesystem tool.

    Read from the (already computed) ``TOOL_PRIVILEGE`` factor's evidence text,
    which names ``"N dangerous tool(s)"`` only when such a grant is present — so
    this stays consistent with the scanner's own dangerous-tool predicate rather
    than re-deriving it.
    """
    return "dangerous tool" in _factor_detail(profile, TrustFactor.TOOL_PRIVILEGE)


def _reach_label(profile: TrustProfile) -> str:
    detail = _factor_detail(profile, TrustFactor.EXPOSURE_REACH)
    if not detail:
        return ""
    return "private LAN" if "private-LAN" in detail else "wildcard / public"


def _server_detail(profile: TrustProfile) -> tuple[tuple[str, str], ...]:
    items = [("grade", profile.grade)]
    for factor in profile.present_factors:
        items.append((f"factor:{factor.factor.value}", factor.detail))
    return tuple(sorted(items))


def _host_key(location: str) -> str:
    return f"host:{location}"


def _server_key(subject: str) -> str:
    return f"server:{subject}"


def _entry_key(subject: str) -> str:
    return f"entry:{subject}"


def _cred_key(sha256_8: str, length: int) -> str:
    return f"cred:{sha256_8}:{length}"


def _target_key(target_id: str) -> str:
    return f"target:{target_id}"


def build_graph(
    profiles: Sequence[TrustProfile],
    inventory: Inventory | None,
    secret_holders: Mapping[str, Sequence[CredRef]],
) -> AttackGraph:
    """Build the structural attack-path graph (nodes + edges) — pure, no I/O.

    Args:
        profiles: Trust profiles, one per declared MCP server (Tier 4).
        inventory: The AI/MCP inventory, or ``None`` to build from trust data
            alone. When present, non-loopback listening sockets add ENTRY nodes
            and declared agent hosts add AGENT_HOST nodes.
        secret_holders: Per-subject credential references, keyed by the trust
            profile ``subject`` id. Each :class:`CredRef` carries an env-var key
            name and a fingerprint — never a value.

    Returns:
        An :class:`AttackGraph` with sorted ``nodes`` and ``edges`` and empty
        ``paths`` (enumeration and grading live in :mod:`mcpscan.graph.paths`).
    """
    nodes: dict[str, Node] = {}
    edges: set[tuple[str, str, EdgeKind, str]] = set()

    server_ids: set[str] = set()

    # --- MCP_SERVER + AGENT_HOST + REACHES-entry nodes from trust profiles ---
    for profile in profiles:
        server_id = _server_key(profile.subject)
        server_ids.add(server_id)
        nodes[server_id] = Node(
            id=server_id,
            kind=NodeKind.MCP_SERVER,
            label=profile.server_name,
            detail=_server_detail(profile),
        )

        host_id = _host_key(profile.location)
        nodes.setdefault(
            host_id,
            Node(
                id=host_id,
                kind=NodeKind.AGENT_HOST,
                label=profile.host,
                detail=(("config", profile.location), ("host", profile.host)),
            ),
        )
        edges.add((host_id, server_id, EdgeKind.HOSTS, "declares"))

        if _present(profile, TrustFactor.EXPOSURE_REACH):
            entry_id = _entry_key(profile.subject)
            reach = _reach_label(profile)
            nodes[entry_id] = Node(
                id=entry_id,
                kind=NodeKind.ENTRY,
                label=profile.server_name,
                detail=(("reach", reach), ("surface", "network bind hint")),
            )
            edges.add((entry_id, server_id, EdgeKind.REACHES, reach))

    # --- inventory-derived AGENT_HOST + socket ENTRY nodes -------------------
    if inventory is not None:
        for asset in inventory.assets:
            if asset.kind is AssetKind.AGENT_HOST and asset.location:
                host_id = _host_key(asset.location)
                nodes.setdefault(
                    host_id,
                    Node(
                        id=host_id,
                        kind=NodeKind.AGENT_HOST,
                        label=asset.host or asset.product,
                        detail=(("config", asset.location), ("host", asset.host or asset.product)),
                    ),
                )
            elif asset.source is AssetSource.SOCKET and asset.bind_addr:
                tier = classify_reachability(asset.bind_addr)
                if tier is ReachTier.LOOPBACK:
                    continue
                entry_id = _entry_key(asset.location)
                nodes.setdefault(
                    entry_id,
                    Node(
                        id=entry_id,
                        kind=NodeKind.ENTRY,
                        label=asset.product,
                        detail=(("reach", tier.value), ("socket", asset.location)),
                    ),
                )

    # --- credential fingerprints joined across every holder ------------------
    # Group each distinct credential by (sha256_8, length): who holds it, and
    # which env-var key names named it (for a stable label + target inference).
    cred_holders: dict[tuple[str, int], set[str]] = {}
    cred_keys: dict[tuple[str, int], Counter[str]] = {}
    for subject, refs in secret_holders.items():
        server_id = _server_key(subject)
        if server_id not in server_ids:
            continue  # never draw an edge to a server node we did not create
        for ref in refs:
            fp = ref.fingerprint
            key = (fp.sha256_8, fp.length)
            cred_holders.setdefault(key, set()).add(subject)
            cred_keys.setdefault(key, Counter())[ref.env_key] += 1

    # Stable per-credential label (most common key name; ties broken by name),
    # target inference, and the CREDENTIAL nodes themselves.
    cred_label: dict[tuple[str, int], str] = {}
    cred_targets: dict[tuple[str, int], set[str]] = {}
    target_labels: dict[str, str] = {}
    for key, keys in cred_keys.items():
        sha256_8, length = key
        best = min(keys.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        cred_label[key] = best
        cred_id = _cred_key(sha256_8, length)
        nodes[cred_id] = Node(
            id=cred_id,
            kind=NodeKind.CREDENTIAL,
            label=best,
            detail=(
                ("fingerprint", f"sha256:{sha256_8}"),
                ("holders", str(len(cred_holders[key]))),
                ("length", str(length)),
            ),
        )
        targets: set[str] = set()
        for env_key in keys:
            inferred = infer_target(env_key)
            if inferred is not None:
                target_id, label = inferred
                targets.add(target_id)
                target_labels[target_id] = label
        cred_targets[key] = targets

    # --- HOLDS / SHARED_WITH / UNLOCKS / CAN_ACT edges + TARGET nodes --------
    for key, holders in cred_holders.items():
        sha256_8, length = key
        cred_id = _cred_key(sha256_8, length)
        shared = len(holders) >= 2
        for subject in holders:
            server_id = _server_key(subject)
            edges.add((server_id, cred_id, EdgeKind.HOLDS, cred_label[key]))
            if shared:
                edges.add(
                    (
                        cred_id,
                        server_id,
                        EdgeKind.SHARED_WITH,
                        f"shared across {len(holders)} tools",
                    )
                )
        for target_id in cred_targets[key]:
            target_node_id = _target_key(target_id)
            nodes.setdefault(
                target_node_id,
                Node(
                    id=target_node_id,
                    kind=NodeKind.TARGET,
                    label=target_labels[target_id],
                    detail=(("kind", "credential-unlocked"),),
                ),
            )
            edges.add((cred_id, target_node_id, EdgeKind.UNLOCKS, target_labels[target_id]))

    # CAN_ACT: a privileged server can act on the targets unlocked by the
    # credentials it holds (the edge that makes a pivot actionable), plus the
    # local machine when it auto-approves a dangerous exec/shell/filesystem tool.
    for profile in profiles:
        server_id = _server_key(profile.subject)
        if _present(profile, TrustFactor.TOOL_PRIVILEGE):
            for ref in secret_holders.get(profile.subject, ()):
                fp = ref.fingerprint
                for target_id in cred_targets.get((fp.sha256_8, fp.length), ()):
                    edges.add(
                        (
                            server_id,
                            _target_key(target_id),
                            EdgeKind.CAN_ACT,
                            "wields privileged tools",
                        )
                    )
        if _has_dangerous_tools(profile):
            shell_id = _target_key(_LOCAL_SHELL_ID)
            nodes.setdefault(
                shell_id,
                Node(
                    id=shell_id,
                    kind=NodeKind.TARGET,
                    label=_LOCAL_SHELL_LABEL,
                    detail=(("kind", "dangerous-tool"),),
                ),
            )
            edges.add((server_id, shell_id, EdgeKind.CAN_ACT, "auto-approved dangerous tool"))

    ordered_nodes = tuple(sorted(nodes.values(), key=lambda n: (n.kind.value, n.id)))
    ordered_edges = tuple(
        Edge(src=src, dst=dst, kind=kind, detail=detail)
        for src, dst, kind, detail in sorted(edges, key=lambda e: (e[2].value, e[0], e[1], e[3]))
    )
    return AttackGraph(
        schema_version=GRAPH_SCHEMA_VERSION,
        nodes=ordered_nodes,
        edges=ordered_edges,
    )
