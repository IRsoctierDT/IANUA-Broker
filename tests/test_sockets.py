# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Enumeration logic tests via a psutil mock (T-201, FR-D1).

The ``psutil`` stand-in lives in ``conftest.py`` (``fake_psutil`` / ``make_conn``
fixtures) so it can be shared with the engine integration tests.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Callable
from typing import Any

import pytest

from mcpscan.discovery import sockets
from mcpscan.domain import Severity


def test_enumerates_listening_socket(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
    make_conn: Callable[..., Any],
) -> None:
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil([make_conn("127.0.0.1", 8000)]))
    result = sockets.enumerate_listening()
    assert len(result.sockets) == 1
    assert result.sockets[0].ip == "127.0.0.1"
    assert result.sockets[0].proc_name == "proc100"
    assert result.inspection_incomplete is False


def test_skips_non_listen_and_empty_laddr(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
    make_conn: Callable[..., Any],
) -> None:
    conns = [
        make_conn("127.0.0.1", 1, status="ESTABLISHED"),
        types.SimpleNamespace(status="LISTEN", laddr=(), pid=1),
    ]
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil(conns))
    assert sockets.enumerate_listening().sockets == ()


def test_access_denied_degrades_gracefully(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
) -> None:
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil([], raise_access=True))
    monkeypatch.setattr(sockets, "_lsof_fallback", lambda: None)  # no lsof either
    result = sockets.enumerate_listening()
    assert result.sockets == ()
    assert result.inspection_incomplete is True


def test_access_denied_uses_lsof_fallback(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
) -> None:
    # macOS without root: psutil denies enumeration, but lsof still sees the
    # user's own listeners — the wildcard bind must survive the fallback.
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil([], raise_access=True))
    fallback = sockets.EnumerationResult(
        sockets=(sockets.ListeningSocket(ip="0.0.0.0", port=8199, pid=42, proc_name="python"),),
        inspection_incomplete=True,
    )
    monkeypatch.setattr(sockets, "_lsof_fallback", lambda: fallback)
    result = sockets.enumerate_listening()
    assert result.sockets == fallback.sockets
    assert result.inspection_incomplete is True


def test_parse_lsof_listeners_parses_machine_format() -> None:
    output = (
        "p42\ncpython\nn*:8199\nn127.0.0.1:8080\nn[::1]:8080\n"
        "p77\ncnode\nn*:3000\nn*:3000\nnbogus\n"
    )
    found = sockets.parse_lsof_listeners(output)
    assert sockets.ListeningSocket(ip="0.0.0.0", port=8199, pid=42, proc_name="python") in found
    assert sockets.ListeningSocket(ip="127.0.0.1", port=8080, pid=42, proc_name="python") in found
    assert sockets.ListeningSocket(ip="::1", port=8080, pid=42, proc_name="python") in found
    # Dual-stack duplicate deduped; the malformed name line is skipped.
    assert [s for s in found if s.pid == 77] == [
        sockets.ListeningSocket(ip="0.0.0.0", port=3000, pid=77, proc_name="node")
    ]


def test_lsof_fallback_none_when_lsof_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sockets.shutil, "which", lambda _: None)
    assert sockets._lsof_fallback() is None


def test_lsof_fallback_parses_subprocess_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sockets.shutil, "which", lambda _: "/usr/sbin/lsof")

    def _fake_run(argv: list[str], **_: Any) -> Any:
        assert argv[0] == "/usr/sbin/lsof"
        return types.SimpleNamespace(returncode=0, stdout="p9\ncsrv\nn*:9999\n")

    monkeypatch.setattr(sockets.subprocess, "run", _fake_run)
    result = sockets._lsof_fallback()
    assert result is not None
    assert result.inspection_incomplete is True  # own-user visibility only
    assert result.sockets == (
        sockets.ListeningSocket(ip="0.0.0.0", port=9999, pid=9, proc_name="srv"),
    )


def test_lsof_fallback_none_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sockets.shutil, "which", lambda _: "/usr/sbin/lsof")
    monkeypatch.setattr(
        sockets.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=2, stdout=""),
    )
    assert sockets._lsof_fallback() is None

    def _boom(*_: Any, **__: Any) -> Any:
        raise sockets.subprocess.TimeoutExpired(cmd="lsof", timeout=10)

    monkeypatch.setattr(sockets.subprocess, "run", _boom)
    assert sockets._lsof_fallback() is None


def test_proc_name_denied_marks_incomplete_but_keeps_socket(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
    make_conn: Callable[..., Any],
) -> None:
    # Per-process introspection can be denied even when enumeration succeeds:
    # the socket is still reported, with proc_name=None and incomplete=True (FR-D1).
    fake = fake_psutil([make_conn("127.0.0.1", 8000, pid=100)], raise_proc_access=True)
    monkeypatch.setitem(sys.modules, "psutil", fake)
    result = sockets.enumerate_listening()
    assert len(result.sockets) == 1
    assert result.sockets[0].proc_name is None
    assert result.inspection_incomplete is True


def test_classify_exposure_branches() -> None:
    # Loopback -> no exposure; wildcard/routable -> CRITICAL; unparseable -> HIGH.
    assert sockets.classify_exposure("127.0.0.1") is None
    assert sockets.classify_exposure("0.0.0.0") is Severity.CRITICAL
    assert sockets.classify_exposure("192.168.1.10") is Severity.CRITICAL
    assert sockets.classify_exposure("not-an-ip") is Severity.HIGH
