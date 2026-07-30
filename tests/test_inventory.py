"""Tier-1 inventory: classification signals, collection, rendering, sanitizing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpscan.adapters.base import ServerDecl
from mcpscan.discovery.probe import NonLoopbackProbeError
from mcpscan.discovery.sockets import ListeningSocket
from mcpscan.inventory import AssetKind, AssetSource, Confidence, collect_inventory
from mcpscan.inventory.classify import agent_host_asset, classify_declared, classify_socket
from mcpscan.inventory.fingerprint import _sanitize, fetch_snippet
from mcpscan.inventory.render import render_json_inventory, render_terminal_inventory
from mcpscan.report import RenderOptions


def _sock(
    ip: str = "127.0.0.1",
    port: int = 11434,
    pid: int | None = 42,
    proc: str | None = None,
) -> ListeningSocket:
    return ListeningSocket(ip=ip, port=port, pid=pid, proc_name=proc)


def _no_response(host: str, port: int, path: str) -> tuple[int, str] | None:
    return None


# --- signal tier 1: process names ---
def test_proc_name_identifies_ollama_with_high_confidence() -> None:
    asset = classify_socket(_sock(proc="ollama"), _no_response)
    assert asset is not None
    assert asset.kind is AssetKind.MODEL_SERVER
    assert asset.product == "Ollama"
    assert asset.confidence is Confidence.HIGH
    assert any("process name" in e for e in asset.evidence)


def test_proc_name_is_case_insensitive_and_strips_exe() -> None:
    asset = classify_socket(_sock(proc="Qdrant.exe", port=6333), _no_response)
    assert asset is not None
    assert asset.kind is AssetKind.VECTOR_DB and asset.product == "Qdrant"
    assert asset.confidence is Confidence.HIGH


def test_proc_name_beats_endpoint_fingerprint() -> None:
    # vLLM serves the generic OpenAI surface; the process identity must win.
    def fetch(host: str, port: int, path: str) -> tuple[int, str] | None:
        return (200, '{"object": "list", "data": []}') if path == "/v1/models" else None

    asset = classify_socket(_sock(proc="vllm", port=8001), fetch)
    assert asset is not None
    assert asset.product == "vLLM" and asset.confidence is Confidence.HIGH
    # Both signals are kept as evidence.
    assert len(asset.evidence) == 2


# --- signal tier 2: endpoint fingerprints ---
def test_ollama_endpoint_fingerprint() -> None:
    def fetch(host: str, port: int, path: str) -> tuple[int, str] | None:
        return (200, '{"models": []}') if path == "/api/tags" else None

    asset = classify_socket(_sock(proc="mystery", port=9999), fetch)
    assert asset is not None
    assert asset.product == "Ollama" and asset.confidence is Confidence.HIGH


def test_generic_openai_surface_is_medium_confidence() -> None:
    def fetch(host: str, port: int, path: str) -> tuple[int, str] | None:
        return (200, '{"object": "list"}') if path == "/v1/models" else None

    asset = classify_socket(_sock(proc="python3", port=9999), fetch)
    assert asset is not None
    assert asset.kind is AssetKind.INFERENCE_ENDPOINT
    assert asset.confidence is Confidence.MEDIUM


def test_mcp_transport_response_classifies_as_mcp_server() -> None:
    def fetch(host: str, port: int, path: str) -> tuple[int, str] | None:
        return (200, "event: endpoint") if path == "/sse" else None

    asset = classify_socket(_sock(proc="node", port=3000), fetch)
    assert asset is not None
    assert asset.kind is AssetKind.MCP_SERVER and asset.confidence is Confidence.MEDIUM


def test_non_loopback_bind_is_never_probed() -> None:
    def fetch(host: str, port: int, path: str) -> tuple[int, str] | None:  # pragma: no cover
        raise AssertionError("must not probe a non-loopback-reachable bind")

    # Specific routable bind: probing 127.0.0.1 would hit a different service.
    asset = classify_socket(_sock(ip="192.168.1.50", port=11434, proc=None), fetch)
    assert asset is not None  # still classified — via the port hint
    assert asset.confidence is Confidence.LOW


def test_wildcard_bind_is_probed_via_loopback() -> None:
    calls: list[str] = []

    def fetch(host: str, port: int, path: str) -> tuple[int, str] | None:
        calls.append(host)
        return (200, '{"models": []}') if path == "/api/tags" else None

    asset = classify_socket(_sock(ip="0.0.0.0", port=11434, proc=None), fetch)
    assert asset is not None and asset.product == "Ollama"
    assert set(calls) == {"127.0.0.1"}


# --- signal tier 3: port hints ---
def test_port_hint_alone_is_low_confidence() -> None:
    asset = classify_socket(_sock(proc="mystery", port=19530), _no_response)
    assert asset is not None
    assert asset.kind is AssetKind.VECTOR_DB and asset.product == "Milvus"
    assert asset.confidence is Confidence.LOW


def test_unrecognized_socket_is_not_inventoried() -> None:
    # A plain web server is scan's exposure concern, not an AI asset.
    assert classify_socket(_sock(proc="nginx", port=8080), _no_response) is None


# --- config-side classification ---
def test_declared_server_is_mcp_server_asset() -> None:
    decl = ServerDecl(name="db", command="npx", args=("-y", "db-mcp-server@1.2.3"))
    asset = classify_declared(decl, "/cfg/.mcp.json", "claude")
    assert asset.kind is AssetKind.MCP_SERVER
    assert asset.source is AssetSource.CONFIG
    assert asset.product == "npx db-mcp-server@1.2.3"
    assert asset.server_name == "db" and asset.host == "claude"


def test_agent_host_asset_names_the_host() -> None:
    asset = agent_host_asset("/cfg/.mcp.json", "cursor")
    assert asset.kind is AssetKind.AGENT_HOST and asset.product == "cursor"


# --- fingerprint probe trust boundary ---
def test_fetch_snippet_refuses_non_loopback() -> None:
    with pytest.raises(NonLoopbackProbeError):
        fetch_snippet("192.168.1.20", 8000, "/")


def test_fetch_snippet_returns_none_when_nothing_listens() -> None:
    # Port 9 (discard) is essentially never bound; connection refused -> None.
    assert fetch_snippet("127.0.0.1", 9, "/") is None


def test_sanitize_strips_non_printables_and_lowercases() -> None:
    assert _sanitize(b'{"Models": []}\x00\x1b[31mEVIL') == '{"models": []}[31mevil'


# --- collection end to end (fake sockets, real config discovery) ---
def _fake_enumeration(monkeypatch: pytest.MonkeyPatch, socks: tuple[ListeningSocket, ...]) -> None:
    from mcpscan.discovery.sockets import EnumerationResult

    monkeypatch.setattr(
        "mcpscan.inventory.collect.enumerate_listening",
        lambda: EnumerationResult(sockets=socks, inspection_incomplete=False),
    )


def test_collect_finds_config_and_socket_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"db": {"command": "npx", "args": ["db-mcp-server@1.0.0"]}}}),
        encoding="utf-8",
    )
    _fake_enumeration(monkeypatch, (_sock(proc="ollama", port=11434),))

    inv = collect_inventory(roots=[tmp_path], system="Linux", env={}, probe=False)
    kinds = [a.kind for a in inv.assets]
    assert AssetKind.AGENT_HOST in kinds  # the .mcp.json evidences a Claude host
    assert AssetKind.MCP_SERVER in kinds  # the declared server
    assert AssetKind.MODEL_SERVER in kinds  # the running Ollama


def test_collect_dedupes_dual_stack_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    socks = (
        ListeningSocket(ip="127.0.0.1", port=11434, pid=7, proc_name="ollama"),
        ListeningSocket(ip="::1", port=11434, pid=7, proc_name="ollama"),
    )
    _fake_enumeration(monkeypatch, socks)
    inv = collect_inventory(roots=[], system="Linux", env={}, probe=False)
    assert len([a for a in inv.assets if a.kind is AssetKind.MODEL_SERVER]) == 1


def test_collect_is_deterministically_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    socks = (
        ListeningSocket(ip="127.0.0.1", port=6333, pid=1, proc_name="qdrant"),
        ListeningSocket(ip="127.0.0.1", port=11434, pid=2, proc_name="ollama"),
    )
    _fake_enumeration(monkeypatch, socks)
    inv = collect_inventory(roots=[], system="Linux", env={}, probe=False)
    assert [a.product for a in inv.assets] == ["Ollama", "Qdrant"]


def test_collect_without_sockets_is_config_only(tmp_path: Path) -> None:
    inv = collect_inventory(
        roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False, probe=False
    )
    assert inv.assets == ()


# --- rendering ---
def _inventory(monkeypatch: pytest.MonkeyPatch) -> object:
    _fake_enumeration(monkeypatch, (_sock(proc="ollama", port=11434),))
    return collect_inventory(roots=[], system="Linux", env={}, probe=False)


def test_terminal_render_groups_by_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    inv = collect_inventory(roots=[], system="Linux", env={}, enumerate_sockets=False)
    out = render_terminal_inventory(inv, RenderOptions())  # type: ignore[arg-type]
    assert "No AI/MCP assets discovered" in out

    _fake_enumeration(monkeypatch, (_sock(proc="ollama", port=11434),))
    inv = collect_inventory(roots=[], system="Linux", env={}, probe=False)
    out = render_terminal_inventory(inv, RenderOptions())
    assert "Model servers (1)" in out and "Ollama" in out and "127.0.0.1:11434" in out


def test_json_render_is_stable_and_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_enumeration(monkeypatch, (_sock(proc="ollama", port=11434),))
    inv = collect_inventory(roots=[], system="Linux", env={}, probe=False)
    first = render_json_inventory(inv, RenderOptions())
    second = render_json_inventory(inv, RenderOptions())
    assert first == second  # byte-stable
    payload = json.loads(first)
    assert payload["schema_version"] == "1.0"
    asset = payload["assets"][0]
    assert asset["kind"] == "model_server" and asset["confidence"] == "high"


def test_json_render_relativizes_config_paths(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    inv = collect_inventory(
        roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False, probe=False
    )
    out = render_json_inventory(inv, RenderOptions(home=str(tmp_path)))
    assert json.loads(out)["assets"][0]["location"].startswith("~")


def test_fetch_snippet_success_path_returns_sanitized_body() -> None:
    # A real (throwaway) loopback HTTP server exercises the full request path.
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b'{"Models": []}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:  # silence test output
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        snippet = fetch_snippet("127.0.0.1", server.server_port, "/api/tags")
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert snippet == (200, '{"models": []}')


def test_collect_skips_unreadable_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpscan.io_safe import SafeReadError

    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")

    def boom(path: object, root: object) -> str:
        raise SafeReadError("unreadable")

    monkeypatch.setattr("mcpscan.inventory.collect.safe_read_text", boom)
    inv = collect_inventory(
        roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False, probe=False
    )
    assert inv.assets == ()  # skipped gracefully, no crash


def test_default_fetch_wires_the_real_fingerprint_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcpscan.inventory.collect as collect_mod
    import mcpscan.inventory.fingerprint as fp

    monkeypatch.setattr(fp, "fetch_snippet", lambda host, port, path: (200, f"{host}:{port}{path}"))
    assert collect_mod._default_fetch("127.0.0.1", 80, "/x") == (200, "127.0.0.1:80/x")


def test_terminal_render_shows_declared_server_details(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"db": {"command": "npx", "args": ["db-mcp-server@1.0.0"]}}}),
        encoding="utf-8",
    )
    inv = collect_inventory(
        roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False, probe=False
    )
    out = render_terminal_inventory(inv, RenderOptions(home=str(tmp_path)))
    assert "Agent hosts (1)" in out and "MCP servers (1)" in out
    assert "'db'" in out  # the declared server name
    assert "~" in out  # config path relativized


def test_collect_ignores_unclassified_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    # nginx is not AI infrastructure — it must not appear in the inventory.
    _fake_enumeration(monkeypatch, (_sock(proc="nginx", port=8080),))
    inv = collect_inventory(roots=[], system="Linux", env={}, probe=False)
    assert inv.assets == ()


def test_terminal_render_flags_incomplete_inspection(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpscan.discovery.sockets import EnumerationResult

    monkeypatch.setattr(
        "mcpscan.inventory.collect.enumerate_listening",
        lambda: EnumerationResult(sockets=(), inspection_incomplete=True),
    )
    inv = collect_inventory(roots=[], system="Linux", env={}, probe=False)
    out = render_terminal_inventory(inv, RenderOptions())
    assert "inspection incomplete" in out


def test_404_on_mcp_paths_is_negative_evidence() -> None:
    # A generic API server answers /mcp with 404 — that must NOT classify.
    def fetch(host: str, port: int, path: str) -> tuple[int, str] | None:
        return (404, "not found")

    assert classify_socket(_sock(proc="uvicorn", port=9000), fetch) is None


def test_405_on_mcp_path_classifies() -> None:
    # Streamable-HTTP MCP servers often 405 a bare GET — the path exists.
    def fetch(host: str, port: int, path: str) -> tuple[int, str] | None:
        return (405, "method not allowed") if path == "/mcp" else (404, "")

    asset = classify_socket(_sock(proc="node", port=3000), fetch)
    assert asset is not None and asset.kind is AssetKind.MCP_SERVER
    assert "HTTP 405" in asset.evidence[0]
