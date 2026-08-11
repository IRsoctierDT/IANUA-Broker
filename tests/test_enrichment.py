# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Online enrichment + offline-isolation guarantees (T-401, NFR-SEC1, R2)."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Self

import pytest

from mcpscan.checks.pinning import PackageSpec, parse_package_spec
from mcpscan.engine import scan
from mcpscan.enrichment import osv as osv_mod
from mcpscan.enrichment.osv import OsvVuln, parse_osv_response, query_osv

PINNED_CONFIG = {
    "mcpServers": {
        "svc": {"command": "npx", "args": ["-y", "some-mcp-server@1.2.3"]},
    }
}

UNPINNABLE_CONFIG = {
    "mcpServers": {
        "svc": {"command": "node", "args": ["server.js"]},
    }
}


# --- pure spec parsing ---
def test_parse_npm_spec() -> None:
    assert parse_package_spec("npx", ("-y", "pkg@1.2.3")) == PackageSpec("npm", "pkg", "1.2.3")


def test_parse_pypi_spec() -> None:
    assert parse_package_spec("uvx", ("tool==2.0.0",)) == PackageSpec("PyPI", "tool", "2.0.0")


def test_unpinned_spec_returns_none() -> None:
    # No concrete version -> nothing is ever sent online.
    assert parse_package_spec("npx", ("-y", "pkg")) is None


# --- pure OSV parsing ---
def test_parse_osv_response() -> None:
    data = {
        "vulns": [
            {"id": "GHSA-xxxx"},
            {"id": "CVE-1", "database_specific": {"severity": "CRITICAL"}},
        ]
    }
    vulns = parse_osv_response(data)
    assert [v.id for v in vulns] == ["GHSA-xxxx", "CVE-1"]
    assert vulns[1].critical is True


def test_parse_osv_empty() -> None:
    assert parse_osv_response({}) == []
    assert parse_osv_response("nonsense") == []


def test_parse_osv_cvss_9x_is_critical() -> None:
    # No explicit CRITICAL label, but a CVSS vector with a 9.x base score.
    data = {
        "vulns": [
            {
                "id": "CVE-9X",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N 9.8"}],
            }
        ]
    }
    assert parse_osv_response(data)[0].critical is True


def test_parse_osv_low_severity_not_critical() -> None:
    data = {"vulns": [{"id": "CVE-LO", "severity": [{"score": "5.0"}]}]}
    assert parse_osv_response(data)[0].critical is False


def test_parse_osv_skips_non_dict_entries() -> None:
    # A junk (non-dict) entry in the list is dropped, not crashed on.
    assert parse_osv_response({"vulns": ["junk", {"id": "OK"}]}) == [OsvVuln("OK", False)]


# --- query_osv HTTP edge (urlopen injected; never the live service) ---
class _FakeHttpResp:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_query_osv_success(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"vulns": [{"id": "GHSA-net"}]}

    def fake_urlopen(req: Any, timeout: float | None = None) -> _FakeHttpResp:
        return _FakeHttpResp(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    vulns = query_osv("pkg", "1.0.0", "npm")
    assert [v.id for v in vulns] == ["GHSA-net"]


def test_query_osv_network_error_is_fail_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    # Enrichment must never break a scan: any network/parse error -> [].
    def boom(req: Any, timeout: float | None = None) -> Any:
        raise OSError("no network")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert query_osv("pkg", "1.0.0", "npm") == []


# --- engine integration via injected fetch (no real network) ---
def test_online_adds_known_vuln_finding(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(PINNED_CONFIG), encoding="utf-8")

    def fake_fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        assert (name, version, ecosystem) == ("some-mcp-server", "1.2.3", "npm")
        return (("GHSA-demo",), False)

    report = scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=fake_fetch,
    )
    ids = {f.id for s in report.servers for f in s.findings}
    assert "PIN-KNOWN-VULN" in ids
    assert report.generated_with_online is True


def test_default_osv_fetch_wires_real_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # online=True with no injected fetch must reach the real (lazy-imported)
    # query_osv path; we stub query_osv itself so no network is touched.
    (tmp_path / ".mcp.json").write_text(json.dumps(PINNED_CONFIG), encoding="utf-8")

    def fake_query(name: str, version: str, ecosystem: str) -> list[OsvVuln]:
        return [OsvVuln(id="GHSA-real", critical=True)]

    monkeypatch.setattr(osv_mod, "query_osv", fake_query)
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False, online=True)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "PIN-KNOWN-VULN" in ids


def test_online_no_vulns_adds_no_finding(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(PINNED_CONFIG), encoding="utf-8")
    report = scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=lambda name, version, ecosystem: ((), False),
    )
    ids = {f.id for s in report.servers for f in s.findings}
    assert "PIN-KNOWN-VULN" not in ids


def test_online_unpinnable_command_never_queries(tmp_path: Path) -> None:
    # A command with no resolvable package spec must not trigger an OSV lookup.
    (tmp_path / ".mcp.json").write_text(json.dumps(UNPINNABLE_CONFIG), encoding="utf-8")

    def must_not_call(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        raise AssertionError("OSV must not be queried for an unpinnable command")

    report = scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=must_not_call,
    )
    ids = {f.id for s in report.servers for f in s.findings}
    assert "PIN-KNOWN-VULN" not in ids


def test_offline_default_does_not_import_egress_module(tmp_path: Path) -> None:
    # NFR-SEC1 / R2: a default scan must not even load the egress module.
    sys.modules.pop("mcpscan.enrichment.osv", None)
    (tmp_path / ".mcp.json").write_text(json.dumps(PINNED_CONFIG), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    assert "mcpscan.enrichment.osv" not in sys.modules
    assert report.generated_with_online is False


def test_osv_vuln_dataclass() -> None:
    assert OsvVuln(id="X", critical=False).id == "X"
