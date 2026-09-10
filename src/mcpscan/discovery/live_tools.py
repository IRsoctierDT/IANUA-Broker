# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Opt-in live MCP ``tools/list`` against loopback only (assessment).

Explicitly disclosed: this talks to a local MCP HTTP/SSE endpoint the operator
already has listening. It never leaves the host. Disabled unless the CLI flag
is passed so the default scan remains offline-static.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class LiveToolsResult:
    """Outcome of one loopback tools/list attempt."""

    url: str
    ok: bool
    tool_names: tuple[str, ...] = ()
    error: str = ""


def list_tools_loopback(host: str, port: int, *, timeout: float = 2.0) -> LiveToolsResult:
    """POST a JSON-RPC tools/list to loopback only. Never raises."""
    if host not in {"127.0.0.1", "::1", "localhost"}:
        return LiveToolsResult(url="", ok=False, error="non_loopback_refused")
    url = f"http://{host}:{port}/mcp"
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    ).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 — loopback-only
            raw = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return LiveToolsResult(url=url, ok=False, error=type(exc).__name__)
    except RecursionError:
        return LiveToolsResult(url=url, ok=False, error="response_too_deep")
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return LiveToolsResult(url=url, ok=False, error="unparseable")
    tools = []
    if isinstance(data, dict):
        result = data.get("result")
        if isinstance(result, dict):
            listed = result.get("tools")
            if isinstance(listed, list):
                for item in listed:
                    if isinstance(item, dict) and isinstance(item.get("name"), str):
                        tools.append(item["name"])
    return LiveToolsResult(url=url, ok=True, tool_names=tuple(tools))
