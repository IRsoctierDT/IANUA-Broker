# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Version-aware vulnerability check: multi-coord extract + --online query (Feature V).

Extraction is pure and offline; the OSV lookup stays behind ``--online`` and is
exercised only through injected fetchers (never the live service), mirroring
``test_enrichment.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcpscan import engine as engine_mod
from mcpscan.atlas import MAPPINGS
from mcpscan.checks.pinning import PackageSpec
from mcpscan.checks.versions import (
    extract_version_coords,
    extract_version_coords_from_cmdline,
    vuln_known_finding,
)
from mcpscan.domain import Dimension, Severity
from mcpscan.engine import scan

# --- pure multi-coord extraction ---------------------------------------------


def test_extract_multiple_npm_coords_from_one_command() -> None:
    coords = extract_version_coords("npx", ("-p", "left-pad@1.0.0", "some-cli@2.0.0"))
    assert coords == [
        PackageSpec("npm", "left-pad", "1.0.0"),
        PackageSpec("npm", "some-cli", "2.0.0"),
    ]


def test_extract_multiple_pypi_coords() -> None:
    coords = extract_version_coords("uvx", ("--with", "extra==1.0", "tool==2.0"))
    assert coords == [
        PackageSpec("PyPI", "extra", "1.0"),
        PackageSpec("PyPI", "tool", "2.0"),
    ]


def test_extract_python_interpreter_with_pinned_dep() -> None:
    # `python -m x` alone yields nothing; a concrete name==version dep is a coord.
    coords = extract_version_coords("/usr/bin/python3.11", ("-m", "mymod", "requests==2.31.0"))
    assert coords == [PackageSpec("PyPI", "requests", "2.31.0")]


def test_bare_python_interpreter_yields_no_coord() -> None:
    assert extract_version_coords("python3", ("-m", "http.server")) == []


def test_extract_none_for_non_runner_command() -> None:
    # `node server.js` names no ecosystem, so nothing is ever sent online for it.
    assert extract_version_coords("node", ("server.js",)) == []


def test_extract_scoped_npm_package() -> None:
    coords = extract_version_coords("npx", ("-y", "@modelcontextprotocol/server@0.4.1"))
    assert coords == [PackageSpec("npm", "@modelcontextprotocol/server", "0.4.1")]


def test_extract_dedupes_repeated_coords() -> None:
    coords = extract_version_coords("npx", ("pkg@1.2.3", "pkg@1.2.3"))
    assert coords == [PackageSpec("npm", "pkg", "1.2.3")]


def test_extract_skips_unpinned_and_flag_args() -> None:
    # Only concrete coordinates count; a bare package name is never sent online.
    assert extract_version_coords("npx", ("-y", "some-pkg")) == []


# --- cmdline extraction (opt-in process path) --------------------------------


def test_extract_from_cmdline_splits_and_parses() -> None:
    coords = extract_version_coords_from_cmdline("npx -y first@1.0.0 second@2.0.0")
    assert coords == [
        PackageSpec("npm", "first", "1.0.0"),
        PackageSpec("npm", "second", "2.0.0"),
    ]


def test_extract_from_empty_cmdline() -> None:
    assert extract_version_coords_from_cmdline("") == []
    assert extract_version_coords_from_cmdline("   ") == []


def test_extract_from_cmdline_non_runner() -> None:
    assert extract_version_coords_from_cmdline("node /srv/app/server.js") == []


# --- finding shape ------------------------------------------------------------


def test_vuln_known_finding_shape() -> None:
    coord = PackageSpec("npm", "left-pad", "1.0.0")
    f = vuln_known_finding("Server 'svc'", coord, ("GHSA-x", "CVE-y"), "/cfg.json")
    assert f.id == "VULN-KNOWN"
    assert f.dimension is Dimension.PINNING
    assert f.severity is Severity.HIGH
    assert "left-pad@1.0.0" in f.title
    assert "GHSA-x" in f.title and "CVE-y" in f.title
    assert f.location.path == "/cfg.json"


def test_vuln_known_finding_critical() -> None:
    coord = PackageSpec("PyPI", "requests", "2.0.0")
    f = vuln_known_finding("Server 'svc'", coord, ("CVE-crit",), "/cfg.json", critical=True)
    assert f.severity is Severity.CRITICAL


def test_vuln_known_is_mapped_in_atlas() -> None:
    assert "VULN-KNOWN" in MAPPINGS
    assert any(r.ref == "T1195.001" for r in MAPPINGS["VULN-KNOWN"])


# --- engine integration (injected fetch; no live network) --------------------

_MULTI_COORD_CONFIG = {
    "mcpServers": {
        "svc": {"command": "npx", "args": ["-y", "runner-pkg@1.0.0", "extra-dep@2.0.0"]},
    }
}

_BROAD_ONLY_CONFIG = {
    # `python -m` names no *runner* spec (parse_package_spec is None), so the
    # pinned dep is only reachable through the broader coord extraction.
    "mcpServers": {
        "svc": {"command": "python3.11", "args": ["-m", "mymod", "vulnlib==3.0.0"]},
    }
}


def test_online_emits_vuln_known_for_extra_coord(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(_MULTI_COORD_CONFIG), encoding="utf-8")
    queried: list[tuple[str, str, str]] = []

    def fake_fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        queried.append((name, version, ecosystem))
        if name == "extra-dep":
            return (("GHSA-extra",), False)
        return ((), False)  # runner-pkg is clean

    report = scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=fake_fetch,
    )
    findings = [f for s in report.servers for f in s.findings]
    ids = {f.id for f in findings}
    assert "VULN-KNOWN" in ids
    assert "PIN-KNOWN-VULN" not in ids  # runner-pkg had no advisory
    vuln = next(f for f in findings if f.id == "VULN-KNOWN")
    assert "extra-dep@2.0.0" in vuln.title and "GHSA-extra" in vuln.title
    # Each distinct coord is queried exactly once (runner + extra), no dupes.
    assert sorted(queried) == [("extra-dep", "2.0.0", "npm"), ("runner-pkg", "1.0.0", "npm")]


def test_online_broad_coord_without_runner_spec(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(_BROAD_ONLY_CONFIG), encoding="utf-8")

    def fake_fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        assert (name, version, ecosystem) == ("vulnlib", "3.0.0", "PyPI")
        return (("CVE-broad",), True)

    report = scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=fake_fetch,
    )
    findings = [f for s in report.servers for f in s.findings]
    vuln = next(f for f in findings if f.id == "VULN-KNOWN")
    assert vuln.severity is Severity.CRITICAL


def test_online_dedupes_runner_coord_no_double_report(tmp_path: Path) -> None:
    # The single pinned runner spec keeps PIN-KNOWN-VULN and is NOT also reported
    # as VULN-KNOWN, nor queried twice.
    config = {"mcpServers": {"svc": {"command": "npx", "args": ["-y", "pkg@1.2.3"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    queried: list[tuple[str, str, str]] = []

    def fake_fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        queried.append((name, version, ecosystem))
        return (("GHSA-only",), False)

    report = scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=fake_fetch,
    )
    ids = [f.id for s in report.servers for f in s.findings]
    assert ids.count("PIN-KNOWN-VULN") == 1
    assert "VULN-KNOWN" not in ids  # same coord, not double-reported
    assert queried == [("pkg", "1.2.3", "npm")]  # queried exactly once


def test_offline_default_emits_no_vuln_known_and_no_egress(tmp_path: Path) -> None:
    # Offline: no VULN-KNOWN, and the egress module is never even imported.
    sys.modules.pop("mcpscan.enrichment.osv", None)
    (tmp_path / ".mcp.json").write_text(json.dumps(_MULTI_COORD_CONFIG), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "VULN-KNOWN" not in ids
    assert "mcpscan.enrichment.osv" not in sys.modules
    assert report.generated_with_online is False


# --- opt-in process-env cmdline path -----------------------------------------


def _stub_process_envs(monkeypatch: pytest.MonkeyPatch, result: object) -> list[bool]:
    called: list[bool] = []

    def _fake(is_agent: object) -> object:
        called.append(True)
        return result

    monkeypatch.setattr(engine_mod, "iter_agent_process_envs", _fake)
    return called


def test_process_cmdline_vuln_known_when_online(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpscan.discovery.process_env import ProcessEnv, ProcessEnvResult

    entry = ProcessEnv(
        pid=99,
        proc_name="claude",
        env=(("LOG_LEVEL", "debug"),),  # clean env: surfaced only via the vuln coord
        cmdline="npx -y badpkg@6.6.6",
    )
    _stub_process_envs(monkeypatch, ProcessEnvResult(entries=(entry,)))

    def fake_fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        assert (name, version, ecosystem) == ("badpkg", "6.6.6", "npm")
        return (("GHSA-proc",), False)

    report = scan(
        roots=[],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        inspect_process_env=True,
        osv_fetch=fake_fetch,
    )
    procs = [s for s in report.servers if s.id.startswith("process://")]
    assert len(procs) == 1
    vuln = next(f for f in procs[0].findings if f.id == "VULN-KNOWN")
    assert "badpkg@6.6.6" in vuln.title
    assert vuln.location.path == "process://claude[99]"


def test_process_cmdline_not_queried_without_online(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpscan.discovery.process_env import ProcessEnv, ProcessEnvResult

    entry = ProcessEnv(
        pid=99, proc_name="claude", env=(("LOG_LEVEL", "debug"),), cmdline="npx -y badpkg@6.6.6"
    )
    _stub_process_envs(monkeypatch, ProcessEnvResult(entries=(entry,)))

    def must_not_call(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        raise AssertionError("OSV must not be queried offline")

    report = scan(
        roots=[],
        system="Linux",
        env={},
        enumerate_sockets=False,
        inspect_process_env=True,
        osv_fetch=must_not_call,  # ignored: online is False, so no fetcher is built
    )
    # Clean env + no online query => process not surfaced at all.
    assert [s for s in report.servers if s.id.startswith("process://")] == []
