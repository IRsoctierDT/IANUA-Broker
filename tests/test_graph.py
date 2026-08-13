# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Tier-3 attack-path graph: model + pure build + target inference.

Profiles are produced by the real ``trust`` scorer (``profile_server``) so the
graph builder is exercised against exactly the factor evidence production emits,
and credentials are fingerprinted with the real ``fingerprint_secret`` so the
secretless invariant is tested against real fingerprints.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from mcpscan.adapters.base import ServerDecl
from mcpscan.domain import Severity
from mcpscan.graph import (
    GRAPH_SCHEMA_VERSION,
    MAX_HOPS,
    MAX_PATHS,
    AttackGraph,
    AttackPath,
    CredRef,
    Edge,
    EdgeKind,
    Node,
    NodeKind,
    analyze_graph,
    build_graph,
    collect_graph,
    enumerate_paths,
    infer_target,
    overall_grade_for_paths,
    render_dot_graph,
    render_json_graph,
    render_terminal_graph,
)
from mcpscan.inventory.model import (
    INVENTORY_SCHEMA_VERSION,
    Asset,
    AssetKind,
    AssetSource,
    Confidence,
    Inventory,
)
from mcpscan.redaction import fingerprint_secret
from mcpscan.report import RenderOptions
from mcpscan.trust.analyze import profile_server
from mcpscan.trust.model import TrustProfile

_CFG = "/cfg/.mcp.json"
_GITHUB_SECRET = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # nosec B105 (fake test value)
_OTHER_SECRET = "ghp_9876543210ZYXWVUTSRQPONMLKJIHGFEDCBA"  # nosec B105 (fake test value)


def _profile(server: ServerDecl, path: str = _CFG, host: str = "claude") -> TrustProfile:
    return profile_server(server, path, host)


def _cred(env_key: str, value: str) -> CredRef:
    return CredRef(env_key=env_key, fingerprint=fingerprint_secret(value))


def _ids(nodes: Sequence[Node], kind: NodeKind) -> set[str]:
    return {n.id for n in nodes if n.kind is kind}


def _edge_kinds(graph: AttackGraph) -> set[EdgeKind]:
    return {e.kind for e in graph.edges}


def _has_edge(graph: AttackGraph, src: str, dst: str, kind: EdgeKind) -> bool:
    return any(e.src == src and e.dst == dst and e.kind is kind for e in graph.edges)


# --- target inference -------------------------------------------------------
def test_infer_target_known_providers() -> None:
    assert infer_target("GITHUB_TOKEN") == ("github", "GitHub")
    assert infer_target("GH_TOKEN") == ("github", "GitHub")
    assert infer_target("AWS_ACCESS_KEY_ID") == ("aws", "AWS")
    assert infer_target("AWS_SECRET_ACCESS_KEY") == ("aws", "AWS")
    assert infer_target("GOOGLE_APPLICATION_CREDENTIALS") == ("gcp", "Google Cloud")
    assert infer_target("AZURE_CLIENT_SECRET") == ("azure", "Azure")
    assert infer_target("SLACK_BOT_TOKEN") == ("slack", "Slack")
    assert infer_target("DATABASE_URL") == ("database", "Database")
    assert infer_target("POSTGRES_PASSWORD") == ("database", "Database")
    assert infer_target("OPENAI_API_KEY") == ("llm_provider", "LLM provider API")
    assert infer_target("NPM_TOKEN") == ("package_registry", "Package registry")


def test_infer_target_is_case_insensitive() -> None:
    assert infer_target("github_token") == ("github", "GitHub")
    assert infer_target("Aws_Session_Token") == ("aws", "AWS")


def test_infer_target_specific_provider_beats_generic_api_key() -> None:
    # A provider-named key wins over the generic ``API_KEY`` fallback.
    assert infer_target("GITHUB_API_KEY") == ("github", "GitHub")
    assert infer_target("SLACK_API_KEY") == ("slack", "Slack")
    # A bare generic key falls through to the LLM-provider bucket.
    assert infer_target("API_KEY") == ("llm_provider", "LLM provider API")


def test_infer_target_unknown_is_none() -> None:
    assert infer_target("FOO_BAR") is None
    assert infer_target("") is None
    assert infer_target("PATH") is None


# --- model ------------------------------------------------------------------
def test_empty_graph_defaults() -> None:
    graph = build_graph([], None, {})
    assert graph.schema_version == GRAPH_SCHEMA_VERSION
    assert graph.nodes == () and graph.edges == ()
    assert graph.paths == () and graph.overall_grade == "A"
    assert graph.critical_paths == ()


def test_critical_paths_orders_worst_first() -> None:
    high = AttackPath(("a", "b"), (EdgeKind.REACHES,), Severity.HIGH, "h", "r")
    crit = AttackPath(
        ("a", "b", "c"), (EdgeKind.REACHES, EdgeKind.CAN_ACT), Severity.CRITICAL, "c", "r"
    )
    med = AttackPath(("a", "b"), (EdgeKind.REACHES,), Severity.MEDIUM, "m", "r")
    graph = AttackGraph(schema_version="1.0", paths=(high, med, crit))
    assert graph.critical_paths == (crit, high)  # CRITICAL before HIGH; MEDIUM excluded


# --- build: shared-credential cross-server pivot ----------------------------
def _shared_credential_graph() -> AttackGraph:
    exposed = _profile(
        ServerDecl(
            name="db",
            command="node",
            args=("serve", "--host", "0.0.0.0"),
            env=(("GITHUB_TOKEN", _GITHUB_SECRET),),
        )
    )
    autonomous = _profile(
        ServerDecl(
            name="shell",
            command="node",
            auto_approve=("run_command",),
            env=(("GITHUB_TOKEN", _GITHUB_SECRET),),
        )
    )
    holders = {
        exposed.subject: [_cred("GITHUB_TOKEN", _GITHUB_SECRET)],
        autonomous.subject: [_cred("GITHUB_TOKEN", _GITHUB_SECRET)],
    }
    return build_graph([exposed, autonomous], None, holders)


def test_shared_credential_builds_full_pivot_chain() -> None:
    graph = _shared_credential_graph()
    server_db = f"server:{_CFG}#db"
    server_shell = f"server:{_CFG}#shell"
    entry_db = f"entry:{_CFG}#db"
    fp = fingerprint_secret(_GITHUB_SECRET)
    cred = f"cred:{fp.sha256_8}:{fp.length}"

    # nodes: two servers, one host, one entry (db is exposed), one cred, targets.
    assert _ids(graph.nodes, NodeKind.MCP_SERVER) == {server_db, server_shell}
    assert _ids(graph.nodes, NodeKind.ENTRY) == {entry_db}
    assert _ids(graph.nodes, NodeKind.CREDENTIAL) == {cred}
    assert "target:github" in _ids(graph.nodes, NodeKind.TARGET)
    assert "target:local_shell" in _ids(graph.nodes, NodeKind.TARGET)

    # the actionable cross-server chain: entry -> db -> cred -> shell -> github.
    assert _has_edge(graph, entry_db, server_db, EdgeKind.REACHES)
    assert _has_edge(graph, server_db, cred, EdgeKind.HOLDS)
    assert _has_edge(graph, cred, server_shell, EdgeKind.SHARED_WITH)
    assert _has_edge(graph, cred, server_db, EdgeKind.SHARED_WITH)
    assert _has_edge(graph, cred, "target:github", EdgeKind.UNLOCKS)
    assert _has_edge(graph, server_shell, "target:github", EdgeKind.CAN_ACT)
    assert _has_edge(graph, server_shell, "target:local_shell", EdgeKind.CAN_ACT)


def test_privileged_only_server_gets_can_act_exposed_does_not() -> None:
    graph = _shared_credential_graph()
    server_db = f"server:{_CFG}#db"
    # db holds the cred but has no privileged tool: no CAN_ACT to github from db.
    assert not _has_edge(graph, server_db, "target:github", EdgeKind.CAN_ACT)


def test_credential_label_is_the_key_name_never_the_value() -> None:
    graph = _shared_credential_graph()
    cred = next(n for n in graph.nodes if n.kind is NodeKind.CREDENTIAL)
    assert cred.label == "GITHUB_TOKEN"


# --- build: distinct credentials -> no shared pivot -------------------------
def test_distinct_credentials_have_no_shared_edge() -> None:
    a = _profile(ServerDecl(name="a", command="node", env=(("GITHUB_TOKEN", _GITHUB_SECRET),)))
    b = _profile(ServerDecl(name="b", command="node", env=(("GITHUB_TOKEN", _OTHER_SECRET),)))
    holders = {
        a.subject: [_cred("GITHUB_TOKEN", _GITHUB_SECRET)],
        b.subject: [_cred("GITHUB_TOKEN", _OTHER_SECRET)],
    }
    graph = build_graph([a, b], None, holders)
    assert len(_ids(graph.nodes, NodeKind.CREDENTIAL)) == 2
    assert EdgeKind.SHARED_WITH not in _edge_kinds(graph)


# --- build: lone exposed server, no onward pivot ----------------------------
def test_lone_exposed_server_has_no_pivot_edges() -> None:
    exposed = _profile(ServerDecl(name="db", command="node", args=("serve", "--host", "0.0.0.0")))
    graph = build_graph([exposed], None, {})
    entry_db = f"entry:{_CFG}#db"
    server_db = f"server:{_CFG}#db"
    assert _has_edge(graph, entry_db, server_db, EdgeKind.REACHES)
    # no credential, no shared pivot, no target, no CAN_ACT — only exposure.
    assert _edge_kinds(graph) == {EdgeKind.HOSTS, EdgeKind.REACHES}
    assert _ids(graph.nodes, NodeKind.CREDENTIAL) == set()
    assert _ids(graph.nodes, NodeKind.TARGET) == set()


# --- build: dangerous tool without a credential still reaches local shell ----
def test_dangerous_tool_adds_local_shell_target() -> None:
    shell = _profile(ServerDecl(name="sh", command="node", auto_approve=("bash",)))
    graph = build_graph([shell], None, {})
    server = f"server:{_CFG}#sh"
    assert "target:local_shell" in _ids(graph.nodes, NodeKind.TARGET)
    assert _has_edge(graph, server, "target:local_shell", EdgeKind.CAN_ACT)


def test_wildcard_only_privilege_has_no_local_shell_target() -> None:
    # A wildcard grant is TOOL_PRIVILEGE but not a *dangerous* exec/shell tool.
    wild = _profile(ServerDecl(name="w", command="node", auto_approve=("mcp__*",)))
    graph = build_graph([wild], None, {})
    assert "target:local_shell" not in _ids(graph.nodes, NodeKind.TARGET)


# --- build: credential label prefers the most common key name ----------------
def test_credential_label_prefers_most_common_key() -> None:
    a = _profile(ServerDecl(name="a", command="node", env=(("GITHUB_TOKEN", _GITHUB_SECRET),)))
    b = _profile(ServerDecl(name="b", command="node", env=(("GH_PAT", _GITHUB_SECRET),)))
    c = _profile(ServerDecl(name="c", command="node", env=(("GITHUB_TOKEN", _GITHUB_SECRET),)))
    holders = {
        a.subject: [_cred("GITHUB_TOKEN", _GITHUB_SECRET)],
        b.subject: [_cred("GH_PAT", _GITHUB_SECRET)],
        c.subject: [_cred("GITHUB_TOKEN", _GITHUB_SECRET)],
    }
    graph = build_graph([a, b, c], None, holders)
    cred = next(n for n in graph.nodes if n.kind is NodeKind.CREDENTIAL)
    assert cred.label == "GITHUB_TOKEN"  # 2x GITHUB_TOKEN beats 1x GH_PAT


# --- build: inventory-derived nodes -----------------------------------------
def _inventory(*assets: Asset) -> Inventory:
    return Inventory(schema_version=INVENTORY_SCHEMA_VERSION, assets=tuple(assets))


def test_inventory_non_loopback_socket_adds_entry() -> None:
    sock = Asset(
        kind=AssetKind.MODEL_SERVER,
        product="Ollama",
        source=AssetSource.SOCKET,
        location="0.0.0.0:11434",
        confidence=Confidence.HIGH,
        evidence=("process name 'ollama'",),
        bind_addr="0.0.0.0",
        port=11434,
    )
    graph = build_graph([], _inventory(sock), {})
    assert "entry:0.0.0.0:11434" in _ids(graph.nodes, NodeKind.ENTRY)


def test_inventory_loopback_socket_is_not_an_entry() -> None:
    sock = Asset(
        kind=AssetKind.MODEL_SERVER,
        product="Ollama",
        source=AssetSource.SOCKET,
        location="127.0.0.1:11434",
        confidence=Confidence.HIGH,
        evidence=("process name 'ollama'",),
        bind_addr="127.0.0.1",
        port=11434,
    )
    graph = build_graph([], _inventory(sock), {})
    assert _ids(graph.nodes, NodeKind.ENTRY) == set()


def test_inventory_agent_host_adds_host_node() -> None:
    host = Asset(
        kind=AssetKind.AGENT_HOST,
        product="Claude Desktop",
        source=AssetSource.CONFIG,
        location="/somewhere/claude.json",
        confidence=Confidence.HIGH,
        evidence=("config present",),
        host="claude",
    )
    graph = build_graph([], _inventory(host), {})
    assert "host:/somewhere/claude.json" in _ids(graph.nodes, NodeKind.AGENT_HOST)


# --- invariants: secretless + deterministic ---------------------------------
def test_graph_is_secretless() -> None:
    graph = _shared_credential_graph()
    blob = repr(graph)
    assert _GITHUB_SECRET not in blob
    fp = fingerprint_secret(_GITHUB_SECRET)
    # only the redaction-safe fingerprint handle may appear.
    assert fp.sha256_8 in blob


def test_build_is_deterministic() -> None:
    assert _shared_credential_graph() == _shared_credential_graph()


def test_nodes_and_edges_are_sorted() -> None:
    graph = _shared_credential_graph()
    node_keys = [(n.kind.value, n.id) for n in graph.nodes]
    assert node_keys == sorted(node_keys)
    edge_keys = [(e.kind.value, e.src, e.dst, e.detail) for e in graph.edges]
    assert edge_keys == sorted(edge_keys)


def test_holder_without_a_server_node_is_ignored() -> None:
    # A secret_holders subject with no matching profile must not create a
    # dangling edge to a non-existent server node.
    a = _profile(ServerDecl(name="a", command="node", env=(("GITHUB_TOKEN", _GITHUB_SECRET),)))
    holders = {
        a.subject: [_cred("GITHUB_TOKEN", _GITHUB_SECRET)],
        "/ghost/.mcp.json#x": [_cred("GITHUB_TOKEN", _GITHUB_SECRET)],
    }
    graph = build_graph([a], None, holders)
    node_ids = {n.id for n in graph.nodes}
    for edge in graph.edges:
        assert edge.src in node_ids and edge.dst in node_ids
    # only one real holder -> the credential is not "shared".
    assert EdgeKind.SHARED_WITH not in _edge_kinds(graph)


# --- paths: enumeration, actionability, severity, caps ----------------------
# Node-detail keys the builder writes for present trust factors; the severity
# rules read these to tell an autonomous+privileged server from a gated one.
_FACTOR_AUTONOMY = "factor:autonomy"
_FACTOR_PRIVILEGE = "factor:tool_privilege"


def _entry(node_id: str, label: str = "e", reach: str = "wildcard / public") -> Node:
    return Node(node_id, NodeKind.ENTRY, label, (("reach", reach), ("surface", "hint")))


def _server(
    node_id: str, label: str = "s", *, autonomous: bool = False, privileged: bool = False
) -> Node:
    detail: list[tuple[str, str]] = [("grade", "F")]
    if autonomous:
        detail.append((_FACTOR_AUTONOMY, "auto-approves 1 tool(s) with no human in the loop"))
    if privileged:
        detail.append((_FACTOR_PRIVILEGE, "auto-approves 1 dangerous tool(s)"))
    return Node(node_id, NodeKind.MCP_SERVER, label, tuple(sorted(detail)))


def _target(node_id: str, label: str = "T") -> Node:
    return Node(node_id, NodeKind.TARGET, label, (("kind", "credential-unlocked"),))


def _severities(paths: tuple[AttackPath, ...]) -> list[Severity]:
    return [p.severity for p in paths]


def test_shared_credential_pivot_is_one_critical_chain_per_target() -> None:
    graph = _shared_credential_graph()
    paths = enumerate_paths(graph.nodes, graph.edges)
    entry_db = f"entry:{_CFG}#db"
    server_db = f"server:{_CFG}#db"
    server_shell = f"server:{_CFG}#shell"

    # exactly the two cross-server chains — to GitHub and to the local shell —
    # both CRITICAL; the non-actionable cred->UNLOCKS->github chain is excluded.
    assert len(paths) == 2
    assert all(p.severity is Severity.CRITICAL for p in paths)
    targets = {p.nodes[-1] for p in paths}
    assert targets == {"target:github", "target:local_shell"}
    for path in paths:
        assert path.nodes[0] == entry_db
        assert path.nodes[:4] == (entry_db, server_db, _cred_id(), server_shell)
        assert EdgeKind.SHARED_WITH in path.edges and EdgeKind.CAN_ACT in path.edges


def _cred_id() -> str:
    fp = fingerprint_secret(_GITHUB_SECRET)
    return f"cred:{fp.sha256_8}:{fp.length}"


def test_summary_reads_as_the_pivot_chain() -> None:
    graph = _shared_credential_graph()
    to_github = next(
        p for p in enumerate_paths(graph.nodes, graph.edges) if p.nodes[-1] == "target:github"
    )
    assert to_github.summary == (
        "exposed 'db' (wildcard / public bind) -> shared credential GITHUB_TOKEN -> "
        "'shell' (autonomous, dangerous tools) -> GitHub"
    )
    assert "shared credential" in to_github.rationale.lower() or "shared" in to_github.rationale


def test_unlocks_without_a_pivot_is_not_actionable() -> None:
    # A lone exposed server that merely holds a credential unlocking a target has
    # no CAN_ACT / SHARED_WITH pivot -> pure exposure, not an actionable chain.
    exposed = _profile(
        ServerDecl(
            name="db",
            command="node",
            args=("serve", "--host", "0.0.0.0"),
            env=(("GITHUB_TOKEN", _GITHUB_SECRET),),
        )
    )
    holders = {exposed.subject: [_cred("GITHUB_TOKEN", _GITHUB_SECRET)]}
    graph = build_graph([exposed], None, holders)
    assert "target:github" in _ids(graph.nodes, NodeKind.TARGET)  # the target exists
    assert enumerate_paths(graph.nodes, graph.edges) == ()  # but no actionable chain


def test_lone_exposed_server_has_no_paths() -> None:
    exposed = _profile(ServerDecl(name="db", command="node", args=("serve", "--host", "0.0.0.0")))
    graph = build_graph([exposed], None, {})
    assert enumerate_paths(graph.nodes, graph.edges) == ()


def test_distinct_credentials_yield_no_paths() -> None:
    a = _profile(ServerDecl(name="a", command="node", env=(("GITHUB_TOKEN", _GITHUB_SECRET),)))
    b = _profile(ServerDecl(name="b", command="node", env=(("GITHUB_TOKEN", _OTHER_SECRET),)))
    holders = {
        a.subject: [_cred("GITHUB_TOKEN", _GITHUB_SECRET)],
        b.subject: [_cred("GITHUB_TOKEN", _OTHER_SECRET)],
    }
    graph = build_graph([a, b], None, holders)
    # neither server is privileged and no credential is shared -> no pivot.
    assert enumerate_paths(graph.nodes, graph.edges) == ()


def test_severity_critical_for_autonomous_privileged_can_act() -> None:
    nodes = (
        _entry("entry:x"),
        _server("server:x", autonomous=True, privileged=True),
        _target("target:github", "GitHub"),
    )
    edges = (
        Edge("entry:x", "server:x", EdgeKind.REACHES, ""),
        Edge("server:x", "target:github", EdgeKind.CAN_ACT, ""),
    )
    paths = enumerate_paths(nodes, edges)
    assert _severities(paths) == [Severity.CRITICAL]


def test_severity_high_for_private_lan_entry() -> None:
    # A LAN-reachable entry (not internet-facing) ranks HIGH — the tier that the
    # old privilege-vs-autonomy split left unreachable.
    nodes = (
        _entry("entry:x", reach="private LAN"),
        _server("server:x", autonomous=True, privileged=True),
        _target("target:github", "GitHub"),
    )
    edges = (
        Edge("entry:x", "server:x", EdgeKind.REACHES, ""),
        Edge("server:x", "target:github", EdgeKind.CAN_ACT, ""),
    )
    paths = enumerate_paths(nodes, edges)
    assert _severities(paths) == [Severity.HIGH]


def test_severity_critical_for_wildcard_or_public_entry() -> None:
    nodes = (
        _entry("entry:x", reach="wildcard / public"),
        _server("server:x", autonomous=True, privileged=True),
        _target("target:github", "GitHub"),
    )
    edges = (
        Edge("entry:x", "server:x", EdgeKind.REACHES, ""),
        Edge("server:x", "target:github", EdgeKind.CAN_ACT, ""),
    )
    assert _severities(enumerate_paths(nodes, edges)) == [Severity.CRITICAL]


def test_severity_medium_when_entry_has_no_network_reach() -> None:
    # An entry with no network reach (an internal-only chain that needs a prior
    # local foothold) ranks MEDIUM — the total-mapping catch-all.
    nodes = (
        _entry("entry:x", reach=""),
        _server("server:x", autonomous=True, privileged=True),
        _target("target:github", "GitHub"),
    )
    edges = (
        Edge("entry:x", "server:x", EdgeKind.REACHES, ""),
        Edge("server:x", "target:github", EdgeKind.CAN_ACT, ""),
    )
    assert _severities(enumerate_paths(nodes, edges)) == [Severity.MEDIUM]


def _line_graph(hops: int) -> tuple[tuple[Node, ...], tuple[Edge, ...]]:
    """A linear entry -> server... -> target chain of exactly ``hops`` edges."""
    nodes: list[Node] = [_entry("entry:0")]
    for i in range(1, hops):
        nodes.append(_server(f"server:{i}", autonomous=True, privileged=True))
    nodes.append(_target("target:t"))
    ids = [n.id for n in nodes]
    edges: list[Edge] = []
    for i in range(hops):
        kind = EdgeKind.CAN_ACT if i == hops - 1 else EdgeKind.REACHES
        edges.append(Edge(ids[i], ids[i + 1], kind, ""))
    return tuple(nodes), tuple(edges)


def test_depth_cap_admits_chain_at_the_limit() -> None:
    nodes, edges = _line_graph(MAX_HOPS)
    paths = enumerate_paths(nodes, edges)
    assert len(paths) == 1
    assert len(paths[0].edges) == MAX_HOPS


def test_depth_cap_drops_chain_over_the_limit() -> None:
    nodes, edges = _line_graph(MAX_HOPS + 1)
    assert enumerate_paths(nodes, edges) == ()


def test_depth_cap_over_the_limit_flags_truncation() -> None:
    # Dropping a chain at the depth cap must disclose the truncation, not swallow
    # it silently (a longer real chain would otherwise vanish with no signal).
    nodes, edges = _line_graph(MAX_HOPS + 1)
    analyzed = analyze_graph(AttackGraph(schema_version="1.0", nodes=nodes, edges=edges))
    assert analyzed.paths == ()
    assert analyzed.truncated is True


def _fan_out_graph(count: int) -> AttackGraph:
    """``count`` independent entry -> server -CAN_ACT-> shared-target chains."""
    nodes: list[Node] = [_target("target:t")]
    edges: list[Edge] = []
    for i in range(count):
        nodes.append(_entry(f"entry:{i}"))
        nodes.append(_server(f"server:{i}", autonomous=True, privileged=True))
        edges.append(Edge(f"entry:{i}", f"server:{i}", EdgeKind.REACHES, ""))
        edges.append(Edge(f"server:{i}", "target:t", EdgeKind.CAN_ACT, ""))
    return AttackGraph(schema_version="1.0", nodes=tuple(nodes), edges=tuple(edges))


def test_enumeration_caps_paths_and_flags_truncation() -> None:
    graph = _fan_out_graph(MAX_PATHS + 5)
    paths = enumerate_paths(graph.nodes, graph.edges)
    assert len(paths) == MAX_PATHS  # the cap bites
    analyzed = analyze_graph(graph)
    assert analyzed.truncated is True
    assert len(analyzed.paths) == MAX_PATHS


def test_no_truncation_below_the_cap() -> None:
    analyzed = analyze_graph(_fan_out_graph(3))
    assert analyzed.truncated is False
    assert len(analyzed.paths) == 3


def test_paths_are_ranked_worst_first() -> None:
    # A CRITICAL (wildcard entry) and a HIGH (private-LAN entry) chain to distinct
    # targets: worst first, deterministic.
    nodes = (
        _entry("entry:c", reach="wildcard / public"),
        _server("server:c", autonomous=True, privileged=True),
        _target("target:crit", "Crit"),
        _entry("entry:h", reach="private LAN"),
        _server("server:h", autonomous=True, privileged=True),
        _target("target:high", "High"),
    )
    edges = (
        Edge("entry:c", "server:c", EdgeKind.REACHES, ""),
        Edge("server:c", "target:crit", EdgeKind.CAN_ACT, ""),
        Edge("entry:h", "server:h", EdgeKind.REACHES, ""),
        Edge("server:h", "target:high", EdgeKind.CAN_ACT, ""),
    )
    paths = enumerate_paths(nodes, edges)
    assert _severities(paths) == [Severity.CRITICAL, Severity.HIGH]
    weights = [p.severity.weight for p in paths]
    assert weights == sorted(weights, reverse=True)


def test_enumerate_paths_is_deterministic() -> None:
    graph = _shared_credential_graph()
    assert enumerate_paths(graph.nodes, graph.edges) == enumerate_paths(graph.nodes, graph.edges)


# --- grading ----------------------------------------------------------------
def test_overall_grade_for_paths_maps_worst_severity() -> None:
    assert overall_grade_for_paths(()) == "A"
    crit = AttackPath(("a", "b"), (EdgeKind.CAN_ACT,), Severity.CRITICAL, "s", "r")
    high = AttackPath(("a", "b"), (EdgeKind.CAN_ACT,), Severity.HIGH, "s", "r")
    med = AttackPath(("a", "b"), (EdgeKind.CAN_ACT,), Severity.MEDIUM, "s", "r")
    assert overall_grade_for_paths((med,)) == "C"
    assert overall_grade_for_paths((high,)) == "D"
    assert overall_grade_for_paths((crit, high, med)) == "F"


def test_analyze_graph_populates_paths_grade_and_leaves_input_pure() -> None:
    graph = _shared_credential_graph()
    analyzed = analyze_graph(graph)
    assert graph.paths == ()  # the frozen input is untouched
    assert analyzed.overall_grade == "F"  # worst chain is CRITICAL
    assert len(analyzed.paths) == 2
    assert analyzed.critical_paths == analyzed.paths  # both CRITICAL, worst-first


def test_empty_graph_analyzes_to_grade_a() -> None:
    analyzed = analyze_graph(build_graph([], None, {}))
    assert analyzed.paths == () and analyzed.overall_grade == "A" and analyzed.truncated is False


# --- secretless over enumerated chains --------------------------------------
def test_enumerated_paths_are_secretless() -> None:
    analyzed = analyze_graph(_shared_credential_graph())
    blob = repr(analyzed.paths)
    assert _GITHUB_SECRET not in blob
    # the share-safe key name is what surfaces in a summary, never the value.
    assert "GITHUB_TOKEN" in blob


# --- collect: end-to-end wiring (the only I/O) ------------------------------
def _write_two_server_config(tmp_path: Path) -> None:
    """A two-server config: an exposed 'db' and an autonomous+privileged 'shell'
    sharing one GitHub credential — the canonical actionable pivot."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "db": {
                        "command": "node",
                        "args": ["serve", "--host", "0.0.0.0"],
                        "env": {"GITHUB_TOKEN": _GITHUB_SECRET},
                    },
                    "shell": {
                        "command": "node",
                        "autoApprove": ["run_command"],
                        "env": {"GITHUB_TOKEN": _GITHUB_SECRET},
                    },
                }
            }
        ),
        encoding="utf-8",
    )


def test_collect_graph_builds_cross_server_critical_chain(tmp_path: Path) -> None:
    _write_two_server_config(tmp_path)
    # inventory=False keeps the collection deterministic (no socket enumeration);
    # env={} isolates it from any real user config.
    graph = collect_graph(roots=[tmp_path], system="Linux", env={}, inventory=False)
    assert graph.overall_grade == "F"
    assert graph.paths and all(p.severity is Severity.CRITICAL for p in graph.paths)
    targets = {p.nodes[-1] for p in graph.paths}
    assert "target:github" in targets
    assert all(EdgeKind.SHARED_WITH in p.edges for p in graph.paths)


def test_collect_graph_pairs_env_key_name_with_fingerprint(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"a": {"command": "node", "env": {"GITHUB_TOKEN": _GITHUB_SECRET}}}}
        ),
        encoding="utf-8",
    )
    graph = collect_graph(roots=[tmp_path], system="Linux", env={}, inventory=False)
    creds = [n for n in graph.nodes if n.kind is NodeKind.CREDENTIAL]
    # labelled by the KEY NAME (never a value) and keyed by the real fingerprint.
    assert [c.label for c in creds] == ["GITHUB_TOKEN"]
    fp = fingerprint_secret(_GITHUB_SECRET)
    assert {c.id for c in creds} == {f"cred:{fp.sha256_8}:{fp.length}"}


def test_collect_graph_credential_key_survives_value_collision(tmp_path: Path) -> None:
    # A non-secret env var holding a value BYTE-IDENTICAL to the secret must not
    # steal the credential's key attribution (the old positional-fingerprint
    # match mislabelled it). The credential is labelled by the secret-named key.
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {
                        "command": "node",
                        "env": {"HARMLESS_COPY": _GITHUB_SECRET, "GITHUB_TOKEN": _GITHUB_SECRET},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    graph = collect_graph(roots=[tmp_path], system="Linux", env={}, inventory=False)
    creds = [n for n in graph.nodes if n.kind is NodeKind.CREDENTIAL]
    # One credential (same fingerprint), and a GitHub target is inferred because
    # the secret-named key GITHUB_TOKEN is correctly attributed.
    assert len(creds) == 1
    targets = {n.label for n in graph.nodes if n.kind is NodeKind.TARGET}
    assert "GitHub" in targets


def test_collect_graph_skips_non_secret_env_entries(tmp_path: Path) -> None:
    # a non-secret env entry preceding the secret must not be paired as a credential.
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {
                        "command": "node",
                        "env": {"NODE_ENV": "production", "GITHUB_TOKEN": _GITHUB_SECRET},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    graph = collect_graph(roots=[tmp_path], system="Linux", env={}, inventory=False)
    creds = [n for n in graph.nodes if n.kind is NodeKind.CREDENTIAL]
    assert [c.label for c in creds] == ["GITHUB_TOKEN"]


def test_collect_graph_is_deterministic(tmp_path: Path) -> None:
    _write_two_server_config(tmp_path)
    first = collect_graph(roots=[tmp_path], system="Linux", env={}, inventory=False)
    second = collect_graph(roots=[tmp_path], system="Linux", env={}, inventory=False)
    assert first == second


def test_collect_graph_is_secretless(tmp_path: Path) -> None:
    _write_two_server_config(tmp_path)
    graph = collect_graph(roots=[tmp_path], system="Linux", env={}, inventory=False)
    assert _GITHUB_SECRET not in repr(graph)


# --- render: terminal, JSON, DOT --------------------------------------------
def _analyzed_shared_graph() -> AttackGraph:
    return analyze_graph(_shared_credential_graph())


def test_render_terminal_shows_arrow_chain_and_severity() -> None:
    out = render_terminal_graph(_analyzed_shared_graph(), RenderOptions())
    assert "attack paths: 2 path(s) (2 critical, 0 high)" in out
    assert "overall grade F" in out
    assert "[CRITICAL]" in out
    assert "->" in out and "GitHub" in out
    assert "why:" in out


def test_render_terminal_no_paths_is_clean() -> None:
    out = render_terminal_graph(analyze_graph(build_graph([], None, {})), RenderOptions())
    assert "0 path(s)" in out
    assert "No cross-server attack paths found." in out


def test_render_terminal_discloses_truncation() -> None:
    graph = analyze_graph(_fan_out_graph(MAX_PATHS + 5))
    assert graph.truncated
    out = render_terminal_graph(graph, RenderOptions())
    assert "truncated" in out.lower()


def test_render_json_is_stable_and_secretless() -> None:
    graph = _analyzed_shared_graph()
    out = render_json_graph(graph, RenderOptions())
    payload = json.loads(out)
    assert payload["schema_version"] == GRAPH_SCHEMA_VERSION
    assert payload["overall_grade"] == "F"
    assert payload["truncated"] is False
    assert payload["nodes"] and payload["edges"] and payload["paths"]
    # secretless: the fake secret never appears; the share-safe key name does.
    assert _GITHUB_SECRET not in out
    assert "GITHUB_TOKEN" in out
    # stable: rendering the same graph twice is byte-identical.
    assert render_json_graph(graph, RenderOptions()) == out


def test_render_json_relativizes_config_path_detail() -> None:
    # an agent-host node carries its config path in detail; it relativizes to ~.
    payload = json.loads(render_json_graph(_analyzed_shared_graph(), RenderOptions(home="/cfg")))
    hosts = [n for n in payload["nodes"] if n["kind"] == "agent_host"]
    assert hosts and hosts[0]["detail"]["config"] == "~/.mcp.json"


def test_render_dot_is_structural_and_secretless() -> None:
    dot = render_dot_graph(_analyzed_shared_graph())
    assert dot.startswith("digraph attack_paths {")
    assert dot.rstrip().endswith("}")
    assert "->" in dot  # it has edges
    assert "shape=diamond" in dot  # a credential node
    assert "can_act" in dot  # the actionable pivot edge label
    assert _GITHUB_SECRET not in dot
    assert render_dot_graph(_analyzed_shared_graph()) == dot  # deterministic
