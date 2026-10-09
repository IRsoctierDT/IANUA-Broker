# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Sandboxed stdio capture (R-LIVE-STDIO, ADR-18).

Protocol tests run the stdlib fixture as a plain child process (our own test
code). The container invariants are asserted on the exact argv; the real
container run is gated behind ``MCPSCAN_CONTAINER_TESTS=1`` on Linux CI.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from _live_mcp_server import FixtureServer, ServerBehaviour

from mcpscan import cli
from mcpscan.discovery import stdio_sandbox
from mcpscan.discovery.live_tools import LiveManifest
from mcpscan.discovery.stdio_sandbox import (
    build_command,
    capture_sandboxed,
    capture_stdio,
    pinned_image,
    valid_server_name,
)
from mcpscan.engine import scan

FIXTURE = str(Path(__file__).with_name("_stdio_mcp_server.py"))
DIGEST = "sha256:" + "a" * 64


def _fixture(mode: str) -> list[str]:
    return [sys.executable, "-u", FIXTURE, mode]


# --- protocol over stdio --------------------------------------------------------


def test_captures_tools_and_skips_notifications() -> None:
    manifest = capture_stdio(_fixture("clean"), "stdio://notes")
    assert manifest.ok, manifest.error
    assert [t.name for t in manifest.tools] == ["read_note", "list_notes"]
    assert manifest.url == "stdio://notes"


def test_silent_server_hits_the_deadline_and_is_killed() -> None:
    started = time.monotonic()
    manifest = capture_stdio(_fixture("silent"), "stdio://x", deadline=1.0)
    assert not manifest.ok and manifest.error == "deadline_exceeded"
    assert time.monotonic() - started < 10


def test_oversized_line_is_rejected() -> None:
    manifest = capture_stdio(_fixture("oversized"), "stdio://x")
    assert not manifest.ok and manifest.error == "response_too_large"


def test_server_that_exits_is_reported() -> None:
    manifest = capture_stdio(_fixture("crash"), "stdio://x")
    assert not manifest.ok and manifest.error in {"stdio_closed", "deadline_exceeded"}


def test_unspawnable_command_is_reported_not_raised() -> None:
    manifest = capture_stdio(["/nonexistent/binary-for-test"], "stdio://x")
    assert not manifest.ok and manifest.error == "spawn_failed"


# --- sandbox invariants ---------------------------------------------------------


def test_container_argv_enforces_every_adr18_control() -> None:
    argv = build_command("/usr/bin/docker", "repo/mcp@" + DIGEST, "mcpscan-test")
    joined = " ".join(argv)
    for control in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--pull never",
        "--user 65534:65534",
        "--rm",
    ):
        assert control in joined, control
    assert "noexec" in joined and "--memory" in argv and "--pids-limit" in argv
    # No host environment, mounts, privileges or extra capabilities, ever.
    for forbidden in (
        "-e",
        "--env",
        "--env-file",
        "-v",
        "--volume",
        "--mount",
        "--privileged",
        "--cap-add",
        "--net",
        "host",
    ):
        assert forbidden not in argv, forbidden
    assert argv[-1] == "repo/mcp@" + DIGEST  # image last: no command override


@pytest.mark.parametrize(
    ("ref", "ok"),
    [
        (DIGEST, True),
        ("ghcr.io/acme/mcp@" + DIGEST, True),
        ("acme/mcp:latest", False),
        ("acme/mcp", False),
        ("acme/mcp@sha256:abc", False),
        ("acme/mcp@" + DIGEST + ";rm -rf /", False),
        ("--privileged", False),
    ],
)
def test_only_digest_pinned_images_are_accepted(ref: str, ok: bool) -> None:
    assert pinned_image(ref) is ok
    if not ok:
        with pytest.raises(ValueError):
            build_command("/usr/bin/docker", ref, "c")


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("notes", True),
        ("my.server-1_x", True),
        ("-rm", False),
        ("a b", False),
        ("", False),
        ("x" * 65, False),
    ],
)
def test_server_names_are_allowlisted(name: str, ok: bool) -> None:
    assert valid_server_name(name) is ok


def test_no_runtime_fails_closed_without_spawning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stdio_sandbox.shutil, "which", lambda _name: None)

    def never(_argv: list[str]) -> subprocess.Popen[bytes]:
        raise AssertionError("must not spawn anything without a container runtime")

    manifest = capture_sandboxed("notes", DIGEST, spawner=never)
    assert not manifest.ok and manifest.error == "no_container_runtime"


@pytest.mark.parametrize(
    ("name", "image", "error"),
    [
        ("notes", "acme/mcp:latest", "image_not_pinned"),
        ("--rm", DIGEST, "bad_server_name"),
    ],
)
def test_bad_inputs_are_refused_before_spawning(name: str, image: str, error: str) -> None:
    def never(_argv: list[str]) -> subprocess.Popen[bytes]:
        raise AssertionError("must not spawn")

    manifest = capture_sandboxed(name, image, spawner=never)
    assert not manifest.ok and manifest.error == error


def test_sandboxed_capture_runs_the_container_argv_and_removes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(stdio_sandbox.shutil, "which", lambda name: f"/usr/bin/{name}")
    removed: list[list[str]] = []
    monkeypatch.setattr(
        stdio_sandbox.subprocess, "run", lambda argv, **_kw: removed.append(list(argv))
    )
    seen: list[list[str]] = []

    def spawner(argv: list[str]) -> subprocess.Popen[bytes]:
        seen.append(argv)  # the container command; run the fixture in its place
        return subprocess.Popen(
            _fixture("clean"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    manifest = capture_sandboxed("notes", DIGEST, spawner=spawner)
    assert manifest.ok and manifest.url == "stdio://notes"
    assert seen[0][:2] == ["/usr/bin/podman", "run"] and "--network" in seen[0]
    name = seen[0][seen[0].index("--name") + 1]
    assert removed == [["/usr/bin/podman", "rm", "-f", name]]


def test_runtime_env_never_carries_host_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCPSCAN_CANARY_SECRET", "s3cr3t")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    env = stdio_sandbox._runtime_env()
    assert "MCPSCAN_CANARY_SECRET" not in env and "GITHUB_TOKEN" not in env


# --- engine + CLI ---------------------------------------------------------------


def test_engine_reports_stdio_server_findings_and_cross_transport_shadowing(
    tmp_path: Path,
) -> None:
    home, root = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    root.mkdir()

    def stdio_capture(name: str, _image: str) -> LiveManifest:
        return capture_stdio(_fixture("poisoned"), f"stdio://{name}")

    http_tools = [{"name": "read_note", "description": "Read.", "inputSchema": {}}]
    with FixtureServer(ServerBehaviour(pages=[http_tools])) as srv:
        report = scan(
            roots=[root],
            system="Linux",
            env={"HOME": str(home)},
            enumerate_sockets=False,
            inspect_live_tools=True,
            live_tools_targets=[("127.0.0.1", srv.port, "/mcp")],
            stdio_targets=[("notes", DIGEST)],
            stdio_capture=stdio_capture,
        )
    stdio = next(s for s in report.servers if s.id == "stdio://notes")
    ids = {f.id for f in stdio.findings}
    assert {"LIVE-TOOL-HIDDEN-UNICODE", "LIVE-TOOL-INJECTION-TEXT", "LIVE-TOOL-SHADOW"} <= ids
    assert [t.name for t in stdio.live_tools] == ["read_note"]


def test_stdio_without_runtime_is_an_inspection_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(stdio_sandbox.shutil, "which", lambda _name: None)
    home, root = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    root.mkdir()
    report = scan(
        roots=[root],
        system="Linux",
        env={"HOME": str(home)},
        enumerate_sockets=False,
        inspect_live_tools=True,
        stdio_targets=[("notes", DIGEST)],
    )
    server = next(s for s in report.servers if s.id == "stdio://notes")
    assert server.inspection_incomplete
    assert [f.id for f in server.findings] == ["LIVE-TOOLS-UNAVAILABLE"]
    assert "no_container_runtime" in server.findings[0].title


@pytest.mark.parametrize("text", ["notes=acme/mcp:latest", "notes", "-x=" + DIGEST, "=" + DIGEST])
def test_cli_rejects_unpinned_or_malformed_stdio_targets(text: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        cli._stdio_target(text)


def test_cli_stdio_requires_opt_in_and_discloses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit):
        cli.main(["scan", "--spawn-stdio", "notes=" + DIGEST])
    capsys.readouterr()
    monkeypatch.setattr(stdio_sandbox.shutil, "which", lambda _name: None)
    cli.main(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--inspect-live-tools",
            "--spawn-stdio",
            "notes=" + DIGEST,
        ]
    )
    err = capsys.readouterr().err
    assert "--spawn-stdio runs server 'notes'" in err and "--network none" in err


# --- real container (Linux CI only) ---------------------------------------------


@pytest.mark.skipif(
    os.environ.get("MCPSCAN_CONTAINER_TESTS") != "1" or shutil.which("docker") is None,
    reason="set MCPSCAN_CONTAINER_TESTS=1 on a Linux host with docker",
)
def test_real_container_blocks_network_and_host_env(monkeypatch: pytest.MonkeyPatch) -> None:
    context = Path(__file__).parent
    build = subprocess.run(
        ["docker", "build", "-q", "-f", str(context / "container" / "Dockerfile"), str(context)],
        capture_output=True,
        text=True,
        check=True,
        timeout=600,
    )
    image = build.stdout.strip()
    assert pinned_image(image), image
    monkeypatch.setenv("MCPSCAN_CANARY_SECRET", "must-not-leak")
    manifest = capture_sandboxed("probe", image, runtime="docker", deadline=60)
    assert manifest.ok, manifest.error
    (tool,) = manifest.tools
    assert tool.description == "network=blocked env=clean"
