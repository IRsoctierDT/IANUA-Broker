"""Shared test fixtures and factories.

Centralizes the ``Report``/``Finding`` builders and the psutil mock that were
previously re-defined inline across several test modules, so new tests can reuse
them instead of copy-pasting (see test-coverage plan, P4).
"""

from __future__ import annotations

import types
from collections.abc import Callable, Sequence
from typing import Any

import pytest

from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    Server,
    ServerState,
    Severity,
)


@pytest.fixture(autouse=True)
def _isolated_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point home-dir discovery at an empty temp dir for every test.

    Pipelines default ``env`` to ``os.environ``, so without this a developer
    machine's real host configs (``~/.claude``, Claude Desktop, Cursor, ...)
    leak into any test that runs a real pipeline — e.g. a credential in the
    real Claude Desktop config fails the trust ``--min-grade`` gate tests.
    """
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.delenv("HOMEDRIVE", raising=False)
    monkeypatch.delenv("HOMEPATH", raising=False)


@pytest.fixture
def make_finding() -> Callable[..., Finding]:
    """Factory for a ``Finding`` with sensible defaults; override any field."""

    def _make(
        *,
        id: str = "X",
        dimension: Dimension = Dimension.CREDENTIAL,
        severity: Severity = Severity.CRITICAL,
        title: str = "t",
        path: str = "p",
        remediation: str = "fix",
        rationale: str = "r",
    ) -> Finding:
        return Finding(
            id=id,
            dimension=dimension,
            severity=severity,
            title=title,
            location=Location(path=path),
            remediation=remediation,
            rationale=rationale,
        )

    return _make


@pytest.fixture
def make_report() -> Callable[..., Report]:
    """Factory for a single-server ``Report`` wrapping the given findings."""

    def _make(*findings: Finding, schema_version: str = "1.0") -> Report:
        server = Server(
            id="s",
            bind_addr=None,
            port=None,
            pid=None,
            proc_name=None,
            state=ServerState.DECLARED,
            running=False,
            findings=tuple(findings),
        )
        return Report(
            schema_version=schema_version,
            servers=(server,),
            overall_grade="F" if findings else "A",
            dimension_grades={},
        )

    return _make


class _Addr:
    """Mimic a populated psutil ``addr`` namedtuple (truthy)."""

    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port

    def __bool__(self) -> bool:
        return True


def _build_fake_psutil(
    connections: Sequence[Any],
    *,
    raise_access: bool = False,
    raise_proc_access: bool = False,
) -> types.ModuleType:
    """Build a stand-in ``psutil`` module for socket-enumeration tests.

    Args:
        connections: Connection records ``net_connections`` should yield.
        raise_access: When True, ``net_connections`` raises ``AccessDenied``.
        raise_proc_access: When True, ``Process(pid).name()`` raises
            ``AccessDenied`` — exercises the per-process degradation path.
    """
    mod = types.ModuleType("psutil")
    mod.CONN_LISTEN = "LISTEN"  # type: ignore[attr-defined]

    class Error(Exception):
        pass

    class AccessDenied(Error):  # mirrors real psutil: AccessDenied subclasses Error
        pass

    def net_connections(kind: str = "inet") -> Sequence[Any]:
        if raise_access:
            raise AccessDenied()
        return connections

    class Process:
        def __init__(self, pid: int) -> None:
            self._pid = pid

        def name(self) -> str:
            if raise_proc_access:
                raise AccessDenied()
            return f"proc{self._pid}"

    mod.AccessDenied = AccessDenied  # type: ignore[attr-defined]
    mod.Error = Error  # type: ignore[attr-defined]
    mod.net_connections = net_connections  # type: ignore[attr-defined]
    mod.Process = Process  # type: ignore[attr-defined]
    return mod


def _conn(ip: str, port: int, status: str = "LISTEN", pid: int | None = 100) -> Any:
    return types.SimpleNamespace(status=status, laddr=_Addr(ip, port), pid=pid)


@pytest.fixture
def fake_psutil() -> Callable[..., types.ModuleType]:
    """Factory returning a fake ``psutil`` module (see ``_build_fake_psutil``)."""
    return _build_fake_psutil


@pytest.fixture
def make_conn() -> Callable[..., Any]:
    """Factory for a fake psutil connection record."""
    return _conn
