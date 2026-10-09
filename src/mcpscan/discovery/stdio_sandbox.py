# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Sandboxed stdio MCP tool-manifest capture (R-LIVE-STDIO, ADR-18).

Most local MCP servers speak stdio, so reading their live tool list means
**running their code**. ADR-18 permits that only inside a container, from an
operator-supplied image pinned by digest. This module:

- **Never downloads.** The image must already be present (``--pull never``) and
  is referenced only by an immutable digest (``name@sha256:…`` or a local image
  id ``sha256:…``); tags are refused because they can move.
- **Contains the process:** ``--network none``, ``--read-only`` root,
  ``--cap-drop ALL``, ``no-new-privileges``, an unprivileged ``--user``, a small
  ``noexec`` tmpfs as the only writable path, plus memory, CPU and process-count
  limits. **No host environment and no host mounts** are passed: secrets in the
  operator's environment or home directory are unreachable.
- **Fails closed.** No container runtime, an unpinned image, or a refused
  container is reported as an inspection gap; there is no fallback to running
  the server as a host process.
- **Bounds the protocol** exactly like the HTTP path (the handshake loop is
  shared via :func:`mcpscan.discovery.live_tools.run_capture`), plus a per-line
  cap, an overall deadline, and a guaranteed kill of the container on exit.

Assessment only: the container is started to answer ``tools/list`` and is torn
down immediately; no tool is ever called and nothing is proxied (ADR-17).
"""

from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess  # nosec B404 — fixed argv, shell=False, sandboxed target
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .live_tools import (
    DEFAULT_DEADLINE,
    MAX_BODY_BYTES,
    CaptureSession,
    LiveManifest,
    LiveToolsError,
    run_capture,
)

RUNTIMES: tuple[str, ...] = ("podman", "docker")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_DIGEST = r"sha256:[0-9a-f]{64}"
_IMAGE_RE = re.compile(rf"(?:[a-z0-9][a-z0-9._/:-]{{0,254}}@)?{_DIGEST}")
_LINE_LIMIT = MAX_BODY_BYTES
_EXIT_GRACE = 3.0


@dataclass(frozen=True)
class SandboxLimits:
    """Resource ceilings for one sandboxed server."""

    memory: str = "256m"
    cpus: str = "1"
    pids: int = 64
    tmpfs_size: str = "16m"
    user: str = "65534:65534"  # nobody:nogroup


DEFAULT_LIMITS = SandboxLimits()


def valid_server_name(name: str) -> bool:
    """A sandbox target name: 1–64 chars, ``[A-Za-z0-9._-]``, alphanumeric first."""
    return _NAME_RE.fullmatch(name) is not None


def pinned_image(ref: str) -> bool:
    """True only for an immutable image reference (repo digest or local image id)."""
    return _IMAGE_RE.fullmatch(ref) is not None


def resolve_runtime(preferred: str = "auto") -> str | None:
    """The container runtime binary to use, or None when none is installed.

    ``auto`` prefers podman (daemonless, rootless by default), then docker.
    """
    candidates = RUNTIMES if preferred == "auto" else (preferred,)
    for name in candidates:
        if name in RUNTIMES:
            path = shutil.which(name)
            if path is not None:
                return path
    return None


def build_command(
    runtime: str, image: str, container_name: str, limits: SandboxLimits = DEFAULT_LIMITS
) -> list[str]:
    """The exact, fixed argv that starts the sandboxed server (no shell, no host env).

    The image's own entrypoint starts the server; mcpscan passes no command, no
    environment variables and no volume mounts.
    """
    if not pinned_image(image):
        raise ValueError("image must be pinned by sha256 digest")
    return [
        runtime,
        "run",
        "--rm",
        "-i",
        "--name",
        container_name,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        limits.user,
        "--memory",
        limits.memory,
        "--cpus",
        limits.cpus,
        "--pids-limit",
        str(limits.pids),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={limits.tmpfs_size}",  # nosec B108 — container path
        image,
    ]


def _runtime_env() -> dict[str, str]:
    """Minimal environment for the runtime CLI itself (never forwarded into the container)."""
    keep = ("PATH", "HOME", "XDG_RUNTIME_DIR", "DOCKER_HOST", "CONTAINER_HOST", "SYSTEMROOT")
    return {k: v for k, v in os.environ.items() if k in keep}


class _StdioChannel:
    """Newline-delimited JSON-RPC over a child's stdin/stdout, bounded and deadline-aware.

    A reader thread moves stdout lines into a queue so reads honour the
    deadline on every platform (pipes are not selectable on Windows).
    """

    def __init__(self, proc: subprocess.Popen[bytes], deadline: float) -> None:
        self._proc = proc
        self._deadline = deadline
        self._lines: queue.Queue[bytes | None] = queue.Queue(maxsize=256)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        stdout = self._proc.stdout
        assert stdout is not None  # nosec B101 — set by Popen(stdout=PIPE)
        total = 0
        try:
            while True:
                line = stdout.readline(_LINE_LIMIT + 1)
                if not line:
                    break
                total += len(line)
                if len(line) > _LINE_LIMIT or total > 8 * MAX_BODY_BYTES:
                    self._lines.put(b"\x00oversized")
                    break
                self._lines.put(line)
        except (OSError, ValueError):
            pass
        self._lines.put(None)

    def send(
        self, body: bytes, _headers: dict[str, str], expect_response: bool
    ) -> tuple[int, dict[str, str], bytes]:
        stdin = self._proc.stdin
        assert stdin is not None  # nosec B101 — set by Popen(stdin=PIPE)
        try:
            stdin.write(body + b"\n")
            stdin.flush()
        except (OSError, ValueError) as exc:
            raise LiveToolsError("stdio_closed") from exc
        if not expect_response:
            return 202, {}, b""
        while True:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise LiveToolsError("deadline_exceeded")
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty as exc:
                raise LiveToolsError("deadline_exceeded") from exc
            if line is None:
                raise LiveToolsError("stdio_closed")
            if line == b"\x00oversized":
                raise LiveToolsError("response_too_large")
            stripped = line.strip()
            if stripped.startswith(b"{") and (b'"result"' in stripped or b'"error"' in stripped):
                return 200, {}, stripped
            # Server notifications/requests and log noise are skipped.


Spawner = Callable[[list[str]], "subprocess.Popen[bytes]"]


def _spawn(argv: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # nosec B603 — fixed argv built by build_command, shell=False
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_runtime_env(),
    )


def capture_stdio(
    argv: Sequence[str],
    url: str,
    *,
    deadline: float = DEFAULT_DEADLINE,
    spawner: Spawner = _spawn,
    on_exit: Callable[[], None] | None = None,
) -> LiveManifest:
    """Run the MCP handshake + ``tools/list`` against a child process's stdio. Never raises.

    ``argv`` is the full command to start (for the sandbox, the container run
    command). The child is always terminated before returning.
    """
    try:
        proc = spawner(list(argv))
    except OSError:
        return LiveManifest(url=url, ok=False, error="spawn_failed")
    try:
        channel = _StdioChannel(proc, time.monotonic() + deadline)
        session = CaptureSession(send=channel.send, deadline=time.monotonic() + deadline)
        return run_capture(session, url)
    finally:
        _terminate(proc)
        if on_exit is not None:
            on_exit()


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    try:
        if proc.stdin is not None:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=_EXIT_GRACE)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=_EXIT_GRACE)
        except subprocess.TimeoutExpired:
            pass


def capture_sandboxed(
    name: str,
    image: str,
    *,
    runtime: str = "auto",
    deadline: float = DEFAULT_DEADLINE,
    limits: SandboxLimits = DEFAULT_LIMITS,
    spawner: Spawner = _spawn,
) -> LiveManifest:
    """Capture a stdio server's tool list from inside the ADR-18 sandbox. Never raises.

    Refuses (as an un-inspected result, never a host-process fallback) an
    invalid name, an unpinned image, or a missing container runtime.
    """
    url = f"stdio://{name}" if valid_server_name(name) else "stdio://invalid"
    if not valid_server_name(name):
        return LiveManifest(url=url, ok=False, error="bad_server_name")
    if not pinned_image(image):
        return LiveManifest(url=url, ok=False, error="image_not_pinned")
    binary = resolve_runtime(runtime)
    if binary is None:
        return LiveManifest(url=url, ok=False, error="no_container_runtime")
    container = f"mcpscan-{uuid.uuid4().hex[:16]}"
    argv = build_command(binary, image, container, limits)

    def kill_container() -> None:
        # Belt and braces: the client exiting does not always stop the
        # container, so remove it by its unique name (ignore "no such").
        try:
            subprocess.run(  # nosec B603 — fixed argv, shell=False
                [binary, "rm", "-f", container],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_runtime_env(),
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    return capture_stdio(argv, url, deadline=deadline, spawner=spawner, on_exit=kill_container)
