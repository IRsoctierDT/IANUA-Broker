# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure classification of discovered services into typed assets (Tier 1).

Three signal tiers, strongest first (see :class:`Confidence`):

1. **Process name** — an exact, positively-identifying executable name
   (``ollama``, ``qdrant``, …). HIGH.
2. **Endpoint fingerprint** — a known product marker in the (sanitized)
   response of a well-known path (``/api/tags`` answering with ``"models"`` is
   Ollama). HIGH when product-specific; MEDIUM for the generic
   OpenAI-compatible ``/v1/models`` surface, which many products expose.
3. **Default port** — a hint only (anything can bind 11434). LOW.

All signal tables are data; the classifier itself is a pure function over a
socket observation plus an optional snippet fetcher, so it is fully unit-
testable with a fake fetcher and no network.
"""

from __future__ import annotations

from collections.abc import Callable

from ..adapters.base import ServerDecl
from ..discovery.sockets import ListeningSocket
from .model import Asset, AssetKind, AssetSource, Confidence

# A snippet fetcher: (host, port, path) -> (status, sanitized lowercase body),
# or None when the endpoint did not respond at all.
SnippetFetch = Callable[[str, int, str], "tuple[int, str] | None"]

# --- signal tables -----------------------------------------------------------

# Exact process names (compared case-insensitively, extension-stripped).
_PROC_SIGNATURES: dict[str, tuple[AssetKind, str]] = {
    "ollama": (AssetKind.MODEL_SERVER, "Ollama"),
    "llama-server": (AssetKind.MODEL_SERVER, "llama.cpp server"),
    "vllm": (AssetKind.MODEL_SERVER, "vLLM"),
    "lm-studio": (AssetKind.MODEL_SERVER, "LM Studio"),
    "lmstudio": (AssetKind.MODEL_SERVER, "LM Studio"),
    "text-generation-launcher": (AssetKind.MODEL_SERVER, "Text Generation Inference"),
    "litellm": (AssetKind.LLM_GATEWAY, "LiteLLM"),
    "qdrant": (AssetKind.VECTOR_DB, "Qdrant"),
    "weaviate": (AssetKind.VECTOR_DB, "Weaviate"),
    "milvus": (AssetKind.VECTOR_DB, "Milvus"),
    "chroma": (AssetKind.VECTOR_DB, "Chroma"),
}

# (path, marker-that-must-appear-in-body) -> (kind, product, confidence).
# Ordered: product-specific fingerprints before the generic OpenAI surface.
_ENDPOINT_SIGNATURES: tuple[tuple[str, str, AssetKind, str, Confidence], ...] = (
    ("/api/tags", '"models"', AssetKind.MODEL_SERVER, "Ollama", Confidence.HIGH),
    ("/api/v1/heartbeat", "heartbeat", AssetKind.VECTOR_DB, "Chroma", Confidence.HIGH),
    ("/v1/meta", "weaviate", AssetKind.VECTOR_DB, "Weaviate", Confidence.HIGH),
    ("/", "qdrant", AssetKind.VECTOR_DB, "Qdrant", Confidence.HIGH),
    (
        "/v1/models",
        '"object"',
        AssetKind.INFERENCE_ENDPOINT,
        "OpenAI-compatible API",
        Confidence.MEDIUM,
    ),
)

# Default ports — a hint only, never an identification.
_PORT_HINTS: dict[int, tuple[AssetKind, str]] = {
    11434: (AssetKind.MODEL_SERVER, "Ollama"),
    1234: (AssetKind.MODEL_SERVER, "LM Studio"),
    4000: (AssetKind.LLM_GATEWAY, "LiteLLM"),
    6333: (AssetKind.VECTOR_DB, "Qdrant"),
    6334: (AssetKind.VECTOR_DB, "Qdrant"),
    19530: (AssetKind.VECTOR_DB, "Milvus"),
    8000: (AssetKind.VECTOR_DB, "Chroma"),
}

# MCP transport paths (mirrors discovery.probe.MCP_PATHS).
_MCP_PATHS = ("/mcp", "/sse")


def _normalize_proc(proc_name: str) -> str:
    name = proc_name.lower()
    return name.removesuffix(".exe")


def _match_proc(proc_name: str | None) -> tuple[AssetKind, str] | None:
    if not proc_name:
        return None
    return _PROC_SIGNATURES.get(_normalize_proc(proc_name))


def classify_socket(sock: ListeningSocket, fetch: SnippetFetch | None = None) -> Asset | None:
    """Classify one listening socket into an asset, or ``None`` if unrecognized.

    ``fetch`` (when given) is called only against ``127.0.0.1`` — a loopback or
    wildcard bind is reachable there; a socket bound to a specific non-loopback
    address is classified from process name and port alone, because probing it
    would cross the loopback trust boundary.

    An unrecognized socket returns ``None`` on purpose: a database or web server
    that is not AI infrastructure belongs to ``scan``'s exposure surface, not to
    this inventory.
    """
    evidence: list[str] = []
    kind: AssetKind | None = None
    product = ""
    confidence = Confidence.LOW

    proc_match = _match_proc(sock.proc_name)
    if proc_match is not None:
        kind, product = proc_match
        confidence = Confidence.HIGH
        evidence.append(f"process name {sock.proc_name!r}")

    if fetch is not None and _probeable(sock.ip):
        endpoint = _match_endpoint(sock.port, fetch)
        if endpoint is not None:
            ep_kind, ep_product, ep_conf, ep_evidence = endpoint
            evidence.append(ep_evidence)
            # The process name is the stronger identity; the endpoint result
            # only takes over when no process signature matched.
            if kind is None:
                kind, product, confidence = ep_kind, ep_product, ep_conf

    if kind is None:
        hint = _PORT_HINTS.get(sock.port)
        if hint is not None:
            kind, product = hint
            confidence = Confidence.LOW
            evidence.append(f"default port {sock.port}")

    if kind is None:
        return None

    return Asset(
        kind=kind,
        product=product,
        source=AssetSource.SOCKET,
        location=f"{sock.ip}:{sock.port}",
        confidence=confidence,
        evidence=tuple(evidence),
        bind_addr=sock.ip,
        port=sock.port,
        pid=sock.pid,
        proc_name=sock.proc_name,
    )


def _probeable(ip: str) -> bool:
    """True if the service is reachable via loopback (loopback or wildcard bind)."""
    return ip in {"0.0.0.0", "::", ""} or _is_loopback(ip)  # nosec B104


def _is_loopback(ip: str) -> bool:
    from ..discovery.sockets import is_loopback

    return is_loopback(ip)


def _match_endpoint(
    port: int, fetch: SnippetFetch
) -> tuple[AssetKind, str, Confidence, str] | None:
    """Try each known endpoint signature against 127.0.0.1:``port``."""
    for path, marker, kind, product, conf in _ENDPOINT_SIGNATURES:
        snippet = fetch("127.0.0.1", port, path)
        if snippet is not None and marker in snippet[1]:
            return kind, product, conf, f"GET {path} matched the {product} signature"
    # MCP transports last. Their handshakes vary (SSE vs streamable HTTP, and a
    # bare GET is often answered 405/406), so a non-404 response is the signal:
    # the path *exists* on that server. A 404 is negative evidence — a generic
    # web server 404s /mcp and must not classify — hence MEDIUM, not HIGH.
    for path in _MCP_PATHS:
        snippet = fetch("127.0.0.1", port, path)
        if snippet is not None and snippet[0] != 404:
            return (
                AssetKind.MCP_SERVER,
                "MCP server (HTTP transport)",
                Confidence.MEDIUM,
                f"responded on {path} (HTTP {snippet[0]})",
            )
    return None


def classify_declared(decl: ServerDecl, config_path: str, host: str) -> Asset:
    """Classify a config-declared MCP server (always an MCP server, by definition)."""
    runner = (decl.command or "").rsplit("/", 1)[-1] or "unknown"
    package = next((a for a in decl.args if not a.startswith("-")), None)
    product = f"{runner} {package}" if package else runner
    return Asset(
        kind=AssetKind.MCP_SERVER,
        product=product,
        source=AssetSource.CONFIG,
        location=config_path,
        confidence=Confidence.HIGH,
        evidence=(f"declared in {host} config",),
        host=host,
        server_name=decl.name,
    )


def agent_host_asset(config_path: str, host: str) -> Asset:
    """The asset for the agent host app a discovered config file evidences."""
    return Asset(
        kind=AssetKind.AGENT_HOST,
        product=host,
        source=AssetSource.CONFIG,
        location=config_path,
        confidence=Confidence.HIGH,
        evidence=("config file present",),
        host=host,
    )
