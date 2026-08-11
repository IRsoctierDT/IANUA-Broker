# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""End-to-end dogfood: the full pipeline over a realistic project (ticket T-402).

This is the repo-verifiable half of T-402. It runs the real ``scan`` over a
realistic Claude project (several MCP servers, a permissions allow-list, and a
secret-bearing ``.env``) and asserts the discovered servers, findings, and
grades; it also exercises the live discovery primitives against a *real* loopback
HTTP server and *real* psutil enumeration — no mocks. Only the external part of
the AC (a stakeholder's physical MCP setups + pfSense/Suricata lab) stays a
manual step; see ``docs/STATUS.yaml``.

Socket enumeration here is intentionally scoped to the dedicated discovery
primitives rather than ``scan(enumerate_sockets=True)``: a full machine-wide
enumeration would pick up whatever else the CI runner is listening on, which is
non-deterministic. The config/secret/scope/pinning dimensions are fully
deterministic from files and are asserted exactly.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from mcpscan.discovery.probe import looks_like_mcp, probe_endpoint
from mcpscan.discovery.sockets import enumerate_listening
from mcpscan.domain import Dimension, Report
from mcpscan.engine import scan

# A realistic mix: a server leaking a DB password, an unpinned tool, a server
# auto-approving a shell tool, a well-configured server, and an over-broad
# permission allow-list. Mirrors the kind of setup a real dogfood run scans.
DOGFOOD_CONFIG = {
    "mcpServers": {
        "leaky-db": {
            "command": "npx",
            "args": ["-y", "db-mcp-server"],
            "env": {"POSTGRES_PASSWORD": "S3cr3t-Pa55w0rd-abcdef123456"},
        },
        "unpinned-fetch": {"command": "uvx", "args": ["fetch-mcp"]},
        "yolo-shell": {
            "command": "node",
            "args": ["shell.js"],
            "autoApprove": ["run_command"],
        },
        "good-citizen": {
            "command": "npx",
            "args": ["-y", "weather-mcp@2.1.0"],
            "env": {"LOG_LEVEL": "info"},
        },
    },
    "permissions": {"allow": ["Bash(*)", "Read", "Glob(src/**)"]},
}


@pytest.fixture
def dogfood_project(tmp_path: Path) -> Path:
    (tmp_path / ".mcp.json").write_text(json.dumps(DOGFOOD_CONFIG), encoding="utf-8")
    env_path = tmp_path / ".env"
    env_path.write_text(
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX0123456789\nLOG=info\n",
        encoding="utf-8",
    )
    os.chmod(env_path, 0o644)  # group/world-readable -> CRED-PERMS
    return tmp_path


def _scan(project: Path) -> Report:
    # env={} -> no user-level configs; enumerate_sockets=False -> deterministic.
    return scan(roots=[project], system="Linux", env={}, enumerate_sockets=False)


def _findings_by_server(report: Report) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for server in report.servers:
        key = server.id.rsplit("#", 1)[-1] if "#" in server.id else Path(server.id).name
        out[key] = {f.id for f in server.findings}
    return out


def test_dogfood_discovers_servers_with_expected_findings(dogfood_project: Path) -> None:
    findings = _findings_by_server(_scan(dogfood_project))
    assert findings["leaky-db"] == {"CRED-PLAINTEXT", "PIN-UNPINNED"}
    assert findings["unpinned-fetch"] == {"PIN-UNPINNED"}
    assert findings["yolo-shell"] == {"SCOPE-DANGEROUS-AUTOAPPROVE"}
    assert findings["good-citizen"] == set()  # a clean server must stay silent
    assert findings["permissions"] == {"SCOPE-DANGEROUS-ALLOW"}
    assert findings[".env"] == {"CRED-PERMS", "CRED-PLAINTEXT"}


def test_dogfood_grades_match_rubric(dogfood_project: Path) -> None:
    report = _scan(dogfood_project)
    assert report.overall_grade == "F"  # a Critical plaintext secret => F
    assert report.dimension_grades[Dimension.CREDENTIAL] == "F"
    assert report.dimension_grades[Dimension.TOOL_SCOPE] == "D"
    assert report.dimension_grades[Dimension.PINNING] == "B"
    assert report.dimension_grades[Dimension.EXPOSURE] == "A"  # no exposed sockets in this fixture


def test_dogfood_scan_is_deterministic(dogfood_project: Path) -> None:
    assert _scan(dogfood_project) == _scan(dogfood_project)


# --- live discovery primitives: real server, real psutil, no mocks ---
@pytest.fixture
def live_loopback_server() -> Iterator[int]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args: object) -> None:
            pass  # keep test output quiet

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


def test_probe_detects_live_loopback_endpoint(live_loopback_server: int) -> None:
    port = live_loopback_server
    assert probe_endpoint("127.0.0.1", port, "/mcp", timeout=2.0) is True
    assert looks_like_mcp("127.0.0.1", port, timeout=2.0) is True


def test_probe_false_on_closed_port() -> None:
    assert looks_like_mcp("127.0.0.1", 1, timeout=0.3) is False


def test_real_enumeration_sees_live_loopback_socket(live_loopback_server: int) -> None:
    port = live_loopback_server
    result = enumerate_listening()  # real psutil, no mock
    if result.inspection_incomplete:
        # Some runners (often macOS) deny socket introspection; FR-D1 says we
        # degrade rather than crash. That contract is asserted in test_sockets.py.
        pytest.skip("OS denied socket introspection on this runner (FR-D1 degradation)")
    mine = [s for s in result.sockets if s.port == port]
    assert mine, "live loopback listener was not found by real enumeration"
    assert any(s.ip in {"127.0.0.1", "::1"} for s in mine)
