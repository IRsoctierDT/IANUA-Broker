# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Opt-in live MCP tool-manifest capture against loopback only (R-LIVE-TOOLS).

Explicitly disclosed: this speaks MCP (Streamable HTTP) to a local endpoint the
operator already has listening — ``initialize`` → ``notifications/initialized``
→ paginated ``tools/list`` — and captures each tool's ``name``, ``description``,
``inputSchema``, ``outputSchema`` and ``annotations``. Disabled unless the CLI
flag is passed, so the default scan stays offline-static (ADR-9).

Trust boundary (ADR-1, ADR-12): the server is **untrusted**. Hardening:

- **Loopback only, fail closed.** A non-loopback host is refused before any
  socket is opened.
- **No proxy, no redirects.** ``http.client`` is used directly: it never
  consults ``HTTP(S)_PROXY`` and never follows a ``3xx``, so neither an
  environment variable nor the server can turn this into egress.
- **No credentials.** No ``Authorization`` header or cookie is ever sent.
- **Bounded.** Response body ≤ 1 MiB, JSON nesting ≤ 32, ≤ 2,000 tools, ≤ 50
  pages, per-socket timeout plus an overall deadline. Breaching a bound yields a
  result marked ``truncated`` or an error — never an unbounded read.
- **Never raises.** Every failure becomes a ``LiveManifest`` with ``error`` set,
  which the engine reports as an inspection gap rather than skipping in silence.

Raw descriptions are retained on the result only so the pure checks in
:mod:`mcpscan.checks.live_tools` can analyse them; they are never written to a
report (findings name codepoints, curated phrases, and tool names only).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import time
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from ..domain import LiveToolPrint
from .sockets import is_loopback

MAX_BODY_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_TOOLS = 2000
MAX_PAGES = 50
MAX_NAME_CHARS = 256
MAX_DESCRIPTION_CHARS = 64 * 1024
DEFAULT_TIMEOUT = 2.0
_CHUNK_BYTES = 64 * 1024
DEFAULT_DEADLINE = 10.0
# The client's offered protocol version; the server negotiates its own.
CLIENT_PROTOCOL_VERSION = "2025-06-18"
_CLIENT_INFO = {"name": "mcpscan", "version": "live-tools"}

# (host, port, path, body, headers, socket timeout, monotonic deadline)
#     -> (status, lowercased headers, body)
Transport = Callable[
    [str, int, str, bytes, dict[str, str], float, float], tuple[int, dict[str, str], bytes]
]


@dataclass(frozen=True)
class LiveTool:
    """One tool as advertised by a live ``tools/list`` (untrusted content).

    ``digest`` is the canonical per-tool fingerprint (see :func:`tool_digest`).
    ``description_oversized`` marks a description longer than
    :data:`MAX_DESCRIPTION_CHARS`; it is still fingerprinted in full.
    """

    name: str
    description: str
    input_schema: object
    output_schema: object
    annotations: object
    digest: str
    description_oversized: bool = False


@dataclass(frozen=True)
class LiveManifest:
    """Outcome of one loopback capture.

    ``ok`` means the handshake and at least the first ``tools/list`` page
    succeeded. ``truncated`` means a bound (tools, pages, malformed entries, a
    failed later page) was hit, so the manifest is known to be incomplete.
    """

    url: str
    ok: bool
    tools: tuple[LiveTool, ...] = field(default_factory=tuple)
    error: str = ""
    truncated: bool = False
    malformed_entries: int = 0
    server_protocol_version: str = ""

    @property
    def manifest_digest(self) -> str | None:
        """Order-independent digest of the whole manifest, or None if not captured.

        ``sha256`` over the sorted ``(name, tool digest)`` pairs, so a reordered
        but otherwise identical ``tools/list`` does not register as drift while any
        added, removed, or altered tool does.
        """
        if not self.ok:
            return None
        pairs = sorted((t.name, t.digest) for t in self.tools)
        canonical = json.dumps(pairs, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class LiveToolsError(Exception):
    """Internal control-flow error; its message is a short, value-free code."""


# --- canonicalization ---------------------------------------------------------


def _nfc(value: object) -> object:
    """Recursively NFC-normalize every string (keys included) in a JSON value."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", str(k)): _nfc(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_nfc(v) for v in value]
    return value


def tool_digest(
    name: str,
    description: str,
    input_schema: object,
    output_schema: object,
    annotations: object,
) -> str:
    """Canonical sha256 fingerprint of one tool's security-relevant surface.

    Covers ``name``, ``description``, ``inputSchema``, ``outputSchema`` and
    ``annotations`` — annotations included, so a server that silently relaxes
    ``readOnlyHint``/``destructiveHint`` changes the digest. Strings are NFC
    normalized and JSON is serialized with sorted keys and no whitespace, so the
    same tool always yields the same digest regardless of key order.
    """
    material = _nfc(
        {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "outputSchema": output_schema,
            "annotations": annotations,
        }
    )
    canonical = json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_digest(value: object) -> str:
    canonical = json.dumps(_nfc(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# The standard MCP tool-annotation behaviour hints (spec: tools/annotations).
BEHAVIOUR_HINTS: tuple[str, ...] = (
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
    "readOnlyHint",
)


def mcpseal_pin(name: str, description: str, input_schema: object) -> str:
    """mcpseal-compatible tool pin (hex sha256), for ``.mcp-lock.json`` import.

    mcpseal 0.1.4 hashes exactly ``{name, description, inputSchema}`` as
    canonical JSON (keys sorted at every level, no whitespace, UTF-8, no
    escaping of non-ASCII) and does **not** NFC-normalize. Verified against
    mcpseal's published hash test vectors.
    """
    canonical = json.dumps(
        {"name": name, "description": description, "inputSchema": input_schema},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fingerprint(tool: LiveTool) -> LiveToolPrint:
    """Reduce a captured tool to a secret-free, comparable fingerprint.

    Description and schemas are kept only as digests; of the annotations, only
    the standard boolean behaviour hints that are actually present are kept.
    """
    hints: list[tuple[str, str]] = []
    if isinstance(tool.annotations, dict):
        for hint in BEHAVIOUR_HINTS:
            value = tool.annotations.get(hint)
            if isinstance(value, bool):
                hints.append((hint, "true" if value else "false"))
    return LiveToolPrint(
        name=tool.name,
        digest=tool.digest,
        description_digest=_canonical_digest(tool.description),
        schema_digest=_canonical_digest(
            {"inputSchema": tool.input_schema, "outputSchema": tool.output_schema}
        ),
        annotations=tuple(hints),
        pin_digest=mcpseal_pin(tool.name, tool.description, tool.input_schema),
    )


# --- bounded JSON -------------------------------------------------------------


def _depth_ok(text: str, limit: int = MAX_JSON_DEPTH) -> bool:
    """True if ``text``'s bracket nesting never exceeds ``limit`` (string-aware)."""
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                return False
        elif char in "]}":
            depth -= 1
    return True


def _reject_constant(_value: str) -> object:
    raise LiveToolsError("non_finite_number")


def _parse_json(raw: bytes) -> object:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LiveToolsError("not_utf8") from exc
    if not _depth_ok(text):
        raise LiveToolsError("response_too_deep")
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise LiveToolsError("unparseable") from exc


# --- transport ----------------------------------------------------------------


def _http_post(
    host: str,
    port: int,
    path: str,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
    deadline: float,
) -> tuple[int, dict[str, str], bytes]:
    """POST over plain ``http.client`` to a loopback host; bounded, deadline-checked read.

    The body is read in chunks with the overall ``deadline`` (a
    ``time.monotonic()`` value) checked between chunks, so a server that drips
    one byte per timeout interval cannot hold the scan open. For an SSE response
    the stream is consumed only until the first complete event carrying a
    JSON-RPC response, so a stream held open after the answer is not waited on.
    """
    if not is_loopback(host):
        raise LiveToolsError("non_loopback_refused")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        ctype = resp_headers.get("content-type", "").lower()
        chunks = _bounded_chunks(resp, deadline)
        if ctype.startswith("text/event-stream"):
            payload = _first_sse_response(chunks)
        else:
            payload = b"".join(chunks)
        return resp.status, resp_headers, payload
    except (OSError, http.client.HTTPException) as exc:
        raise LiveToolsError(type(exc).__name__) from exc
    finally:
        conn.close()


def _bounded_chunks(resp: http.client.HTTPResponse, deadline: float) -> Iterator[bytes]:
    """Yield response chunks until EOF, enforcing the size cap and the deadline."""
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise LiveToolsError("deadline_exceeded")
        chunk = resp.read1(_CHUNK_BYTES)
        if not chunk:
            return
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise LiveToolsError("response_too_large")
        yield chunk


def _first_sse_response(chunks: Iterator[bytes]) -> bytes:
    """Return the ``data`` of the first SSE event whose payload is a JSON-RPC response.

    Events without a ``result``/``error`` (server notifications or requests) are
    skipped. Stops consuming ``chunks`` as soon as the response is found.
    """
    buffer = b""
    data_lines: list[bytes] = []

    def flush() -> bytes | None:
        if not data_lines:
            return None
        payload = b"\n".join(data_lines)
        data_lines.clear()
        return payload if _looks_like_response(payload) else None

    for chunk in chunks:
        buffer += chunk
        while True:
            newline = buffer.find(b"\n")
            if newline < 0:
                break
            line, buffer = buffer[:newline].rstrip(b"\r"), buffer[newline + 1 :]
            if line == b"":
                found = flush()
                if found is not None:
                    return found
            elif line.startswith(b"data:"):
                chunk_data = line[5:]
                data_lines.append(chunk_data[1:] if chunk_data.startswith(b" ") else chunk_data)
    if buffer.startswith(b"data:"):
        tail = buffer.rstrip(b"\r")[5:]
        data_lines.append(tail[1:] if tail.startswith(b" ") else tail)
    found = flush()
    if found is not None:
        return found
    raise LiveToolsError("sse_no_response")


def _looks_like_response(payload: bytes) -> bool:
    try:
        obj = _parse_json(payload)
    except LiveToolsError:
        return False
    return isinstance(obj, dict) and ("result" in obj or "error" in obj)


# --- protocol -----------------------------------------------------------------


# (body, headers, expect_response) -> (status, lowercased headers, payload).
# HTTP maps this onto one POST; stdio onto one line written (plus, when a
# response is expected, the matching line read back).
Sender = Callable[[bytes, dict[str, str], bool], tuple[int, dict[str, str], bytes]]


@dataclass
class CaptureSession:
    """MCP client state for one capture over an abstract :data:`Sender`."""

    send: Sender
    deadline: float
    session_id: str | None = None
    protocol_version: str | None = None
    next_id: int = 1

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id is not None:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version is not None:
            headers["MCP-Protocol-Version"] = self.protocol_version
        return headers

    def _post(self, body: bytes, expect_response: bool) -> tuple[int, dict[str, str], bytes]:
        if time.monotonic() > self.deadline:
            raise LiveToolsError("deadline_exceeded")
        return self.send(body, self._headers(), expect_response)

    def request(
        self, method: str, params: dict[str, object]
    ) -> tuple[dict[str, object], dict[str, str]]:
        req_id = self.next_id
        self.next_id += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        ).encode("utf-8")
        status, headers, payload = self._post(body, True)
        if not 200 <= status < 300:
            # 3xx included: redirects are never followed (no off-host hop).
            raise LiveToolsError(f"http_{status}")
        obj = _parse_json(payload)
        if not isinstance(obj, dict) or obj.get("id") != req_id:
            raise LiveToolsError("bad_jsonrpc_response")
        if "error" in obj:
            raise LiveToolsError(f"{method.replace('/', '_')}_error")
        result = obj.get("result")
        if not isinstance(result, dict):
            raise LiveToolsError("bad_jsonrpc_result")
        return result, headers

    def notify(self, method: str) -> None:
        body = json.dumps({"jsonrpc": "2.0", "method": method}).encode("utf-8")
        status, _headers, _payload = self._post(body, False)
        if not 200 <= status < 300:
            raise LiveToolsError(f"http_{status}")


def _session_id(headers: dict[str, str]) -> str | None:
    """Accept a session id only if it is short visible ASCII (spec: 0x21–0x7E)."""
    value = headers.get("mcp-session-id")
    if value is None:
        return None
    if not 0 < len(value) <= 256 or any(not 0x21 <= ord(c) <= 0x7E for c in value):
        raise LiveToolsError("bad_session_id")
    return value


def _parse_tool(item: object) -> LiveTool | None:
    """Validate one ``tools/list`` entry; None if it is malformed."""
    if not isinstance(item, dict):
        return None
    name = item.get("name")
    if not isinstance(name, str) or not 0 < len(name) <= MAX_NAME_CHARS:
        return None
    description = item.get("description")
    if description is None:
        description = ""
    if not isinstance(description, str):
        return None
    input_schema = item.get("inputSchema", {})
    output_schema = item.get("outputSchema")
    annotations = item.get("annotations")
    if not isinstance(input_schema, dict):
        return None
    if output_schema is not None and not isinstance(output_schema, dict):
        return None
    if annotations is not None and not isinstance(annotations, dict):
        return None
    return LiveTool(
        name=name,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=annotations,
        digest=tool_digest(name, description, input_schema, output_schema, annotations),
        description_oversized=len(description) > MAX_DESCRIPTION_CHARS,
    )


def capture_manifest(
    host: str,
    port: int,
    path: str = "/mcp",
    *,
    timeout: float = DEFAULT_TIMEOUT,
    deadline: float = DEFAULT_DEADLINE,
    transport: Transport | None = None,
) -> LiveManifest:
    """Capture a live MCP tool manifest from a loopback endpoint. Never raises.

    Args:
        host: Loopback address; anything else is refused before connecting.
        port: TCP port of the local MCP server.
        path: HTTP path of the Streamable HTTP endpoint (must start with ``/``).
        timeout: Per-socket-operation timeout in seconds.
        deadline: Overall wall-clock budget for the whole capture, in seconds.
        transport: Injected POST function (tests); defaults to :func:`_http_post`.

    Returns:
        A :class:`LiveManifest`; ``ok`` is False with a short ``error`` code on any
        failure.
    """
    if not is_loopback(host):
        return LiveManifest(url="", ok=False, error="non_loopback_refused")
    url = f"http://{host}:{port}{path}"
    if not 0 < port < 65536:
        return LiveManifest(url=url, ok=False, error="bad_port")
    if (
        not path.startswith("/")
        or len(path) > 256
        or any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in path)
    ):
        return LiveManifest(url=url, ok=False, error="bad_path")

    send_http = transport or _http_post

    def send(
        body: bytes, headers: dict[str, str], _expect: bool
    ) -> tuple[int, dict[str, str], bytes]:
        return send_http(host, port, path, body, headers, timeout, session.deadline)

    session = CaptureSession(send=send, deadline=time.monotonic() + deadline)
    return run_capture(session, url)


def run_capture(session: CaptureSession, url: str) -> LiveManifest:
    """Run the handshake and paginated ``tools/list`` over any sender. Never raises.

    Shared by the loopback HTTP path and the sandboxed stdio path
    (:mod:`mcpscan.discovery.stdio_sandbox`), so both apply identical bounds:
    tool and page caps, malformed-entry accounting, and a partial capture
    marked ``truncated`` rather than silently trusted.
    """
    tools: list[LiveTool] = []
    malformed = 0
    truncated = False
    listed_once = False
    try:
        init, headers = session.request(
            "initialize",
            {
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        session.session_id = _session_id(headers)
        negotiated = init.get("protocolVersion")
        if isinstance(negotiated, str) and 0 < len(negotiated) <= 32 and negotiated.isprintable():
            session.protocol_version = negotiated
        session.notify("notifications/initialized")

        cursor: str | None = None
        for _page in range(MAX_PAGES):
            params: dict[str, object] = {} if cursor is None else {"cursor": cursor}
            result, _ = session.request("tools/list", params)
            listed = result.get("tools")
            if not isinstance(listed, list):
                raise LiveToolsError("bad_tools_list")
            listed_once = True
            for item in listed:
                if len(tools) >= MAX_TOOLS:
                    truncated = True
                    break
                tool = _parse_tool(item)
                if tool is None:
                    malformed += 1
                else:
                    tools.append(tool)
            if truncated:
                break
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                break
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
                truncated = True
                break
            cursor = next_cursor
        else:
            truncated = True  # page cap reached with a cursor still pending
    except LiveToolsError as exc:
        if not listed_once:
            return LiveManifest(url=url, ok=False, error=str(exc))
        # A later page failed: keep what was captured but mark it incomplete.
        truncated = True
    return LiveManifest(
        url=url,
        ok=True,
        tools=tuple(tools),
        truncated=truncated or malformed > 0,
        malformed_entries=malformed,
        server_protocol_version=session.protocol_version or "",
    )
