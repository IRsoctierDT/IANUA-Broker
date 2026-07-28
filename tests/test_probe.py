"""Probe trust-boundary tests (T-203): loopback-only, fail closed."""

from __future__ import annotations

from typing import Any

import pytest

from mcpscan.discovery.probe import (
    NonLoopbackProbeError,
    looks_like_mcp,
    probe_endpoint,
)
from mcpscan.discovery.sockets import is_loopback


class _FakeResp:
    def read(self) -> bytes:
        return b""


class _FakeConn:
    """Stand-in for http.client.HTTPConnection that always answers."""

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        self.host = host
        self.port = port

    def request(self, method: str, path: str) -> None:  # bare GET, no creds
        assert method == "GET"

    def getresponse(self) -> Any:
        return _FakeResp()

    def close(self) -> None:
        pass


def test_is_loopback() -> None:
    assert is_loopback("127.0.0.1")
    assert is_loopback("::1")
    assert is_loopback("localhost")
    assert not is_loopback("0.0.0.0")
    assert not is_loopback("192.168.1.10")
    assert not is_loopback("example.com")


def test_probe_refuses_non_loopback() -> None:
    # The probe must NEVER reach out beyond loopback — fail closed.
    with pytest.raises(NonLoopbackProbeError):
        probe_endpoint("192.168.1.10", 8000, "/mcp")
    with pytest.raises(NonLoopbackProbeError):
        probe_endpoint("0.0.0.0", 8000, "/mcp")


def test_probe_loopback_closed_port_returns_false() -> None:
    # Nothing listening on this loopback port -> False, no exception.
    assert probe_endpoint("127.0.0.1", 1, "/mcp", timeout=0.2) is False


def test_probe_responding_endpoint_returns_true(monkeypatch: pytest.MonkeyPatch) -> None:
    # A loopback host that answers the bare GET is reported as responding.
    monkeypatch.setattr("http.client.HTTPConnection", _FakeConn)
    assert probe_endpoint("127.0.0.1", 8000, "/mcp") is True


def test_looks_like_mcp_true_when_any_path_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("http.client.HTTPConnection", _FakeConn)
    assert looks_like_mcp("127.0.0.1", 8000) is True
