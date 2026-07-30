"""Tests for the LAN wiring: verify, probe, and the run_lan orchestration gate."""

from __future__ import annotations

import base64
import http.server
import socket
import sys
import threading
import types
from datetime import UTC, datetime
from pathlib import Path

import pytest

import mcpscan.lan.verify as verify_mod
from mcpscan.domain import Dimension
from mcpscan.lan.probe import ProbeResult, tcp_probe
from mcpscan.lan.runner import LanOutcome, LanRefusal, run_lan
from mcpscan.lan.verify import VerifyResult, verify_ed25519, verify_manifest, verify_ssh

MANIFEST = b"""
authorization_id = "ENG-2026-0710"
operator = "j.doe@example.com"
expires_at = 2026-07-10T23:59:59Z
targets = ["192.168.10.20/32"]
ports = [3000, 8000]
"""
NOW = datetime(2026, 7, 10, 9, 0, 0, tzinfo=UTC)  # before expiry


def _ok_verifier(*_a: object) -> VerifyResult:
    return VerifyResult(True, "ok")


def _exposed(host: str, port: int, timeout: float) -> ProbeResult:
    return ProbeResult(
        host, port, reachable=True, looks_like_mcp=True, evidence="[untrusted] HTTP 200"
    )


def _run(**over: object) -> LanOutcome | LanRefusal:
    kw: dict[str, object] = {
        "manifest_bytes": MANIFEST,
        "now": NOW,
        "invoker": "human",
        "tool_version": "0.6.0",
        "argv": ["mcpscan", "lan"],
        "signature_path": Path("m.sig"),
        "allowed_signers": Path("allowed"),
        "verifier": _ok_verifier,
        "prober": _exposed,
        "sleep": lambda _s: None,
    }
    kw.update(over)
    return run_lan(**kw)  # type: ignore[arg-type]


# --- verify: ed25519 ([crypto] extra) ---
def _crypto_backend_works() -> bool:
    # Some environments ship a cryptography whose native backend can't load; the
    # key ops raise/panic rather than ImportError. Detect and skip those.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        Ed25519PrivateKey.generate().sign(b"x")
    except BaseException:  # noqa: BLE001 - includes pyo3 PanicException on broken backends
        return False
    return True


_CRYPTO_OK = _crypto_backend_works()
_needs_crypto = pytest.mark.skipif(not _CRYPTO_OK, reason="cryptography backend unavailable")


def _ed25519_material(tmp_path: Path, data: bytes, operator: str = "op@example.com"):  # type: ignore[no-untyped-def]
    """Generate a keypair, sign ``data``, and write sig + allowed-signers files."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes_raw()
    sig = key.sign(data)
    sig_path = tmp_path / "auth.sig"
    sig_path.write_bytes(base64.b64encode(sig))
    signers = tmp_path / "allowed"
    signers.write_text(f"{operator} {base64.b64encode(pub_raw).decode()}\n", encoding="utf-8")
    return sig_path, signers


@_needs_crypto
def test_verify_ed25519_success(tmp_path: Path) -> None:
    data = b"the manifest bytes"
    sig, signers = _ed25519_material(tmp_path, data)
    assert verify_ed25519(data, sig, signers, "op@example.com").ok


@_needs_crypto
def test_verify_ed25519_tampered_is_rejected(tmp_path: Path) -> None:
    sig, signers = _ed25519_material(tmp_path, b"original")
    r = verify_ed25519(b"tampered", sig, signers, "op@example.com")
    assert not r.ok and "verification failed" in r.detail


@_needs_crypto
def test_verify_ed25519_unknown_operator(tmp_path: Path) -> None:
    sig, signers = _ed25519_material(tmp_path, b"data")
    r = verify_ed25519(b"data", sig, signers, "someone-else@example.com")
    assert not r.ok and "no ed25519 public key" in r.detail


@_needs_crypto
def test_verify_ed25519_bad_base64_signature(tmp_path: Path) -> None:
    _sig, signers = _ed25519_material(tmp_path, b"data")
    bad = tmp_path / "bad.sig"
    bad.write_bytes(b"!!!not base64!!!")
    r = verify_ed25519(b"data", bad, signers, "op@example.com")
    assert not r.ok and "not valid base64" in r.detail


def test_verify_ed25519_without_crypto_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate the [crypto] extra being absent. Setting the parent alone is not
    # enough when the submodules are already cached in sys.modules (as they are
    # after the real-crypto tests run in CI) — the from-import would still
    # resolve. Setting each imported submodule to None forces ImportError.
    for module in (
        "cryptography",
        "cryptography.exceptions",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
    ):
        monkeypatch.setitem(sys.modules, module, None)
    r = verify_ed25519(b"data", tmp_path / "s", tmp_path / "a", "op")
    assert not r.ok and "crypto" in r.detail


@_needs_crypto
def test_verify_manifest_dispatches_ed25519(tmp_path: Path) -> None:
    data = b"manifest"
    sig, signers = _ed25519_material(tmp_path, data)
    r = verify_manifest(
        scheme="ed25519",
        manifest_bytes=data,
        signature_path=sig,
        allowed_signers=signers,
        operator="op@example.com",
    )
    assert r.ok


def test_verify_manifest_ssh_requires_files() -> None:
    r = verify_manifest(
        scheme="ssh",
        manifest_bytes=b"x",
        signature_path=None,
        allowed_signers=None,
        operator="op",
    )
    assert not r.ok and "requires" in r.detail


def test_verify_manifest_ssh_delegates_to_verifier() -> None:
    r = verify_manifest(
        scheme="ssh",
        manifest_bytes=b"x",
        signature_path=Path("s"),
        allowed_signers=Path("a"),
        operator="op",
        verifier=_ok_verifier,
    )
    assert r.ok


def test_verify_ssh_success(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        verify_mod.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"Good"),
    )
    assert verify_ssh(b"data", Path("s"), Path("a"), "op").ok


def test_verify_ssh_rejects_and_sanitizes(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        verify_mod.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(
            returncode=1, stdout=b"", stderr=b"\x1b[31mBad signature\x1b[0m"
        ),
    )
    r = verify_ssh(b"data", Path("s"), Path("a"), "op")
    assert not r.ok and "Bad signature" in r.detail and "\x1b" not in r.detail


def test_verify_ssh_missing_binary(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def _boom(*_a: object, **_k: object) -> object:
        raise FileNotFoundError

    monkeypatch.setattr(verify_mod.subprocess, "run", _boom)
    r = verify_ssh(b"data", Path("s"), Path("a"), "op")
    assert not r.ok and "ssh-keygen not found" in r.detail


def test_verify_ssh_subprocess_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def _timeout(*_a: object, **_k: object) -> object:
        raise verify_mod.subprocess.TimeoutExpired(cmd="ssh-keygen", timeout=10)

    monkeypatch.setattr(verify_mod.subprocess, "run", _timeout)
    r = verify_ssh(b"data", Path("s"), Path("a"), "op")
    assert not r.ok and "could not run" in r.detail


# --- probe (real socket, loopback only — no external network) ---
def test_tcp_probe_reachable_mcp() -> None:
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_a: object) -> None:
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        result = tcp_probe("127.0.0.1", srv.server_port, timeout=2.0)
        assert result.reachable and result.looks_like_mcp
        assert result.evidence and "HTTP 200" in result.evidence
    finally:
        srv.shutdown()


def test_tcp_probe_unreachable() -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # port now closed -> connection refused
    result = tcp_probe("127.0.0.1", port, timeout=0.5)
    assert not result.reachable and not result.looks_like_mcp


def test_tcp_probe_reachable_but_not_http() -> None:
    # A port that accepts TCP but never speaks HTTP: reachable, not MCP, no evidence.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        result = tcp_probe("127.0.0.1", listener.getsockname()[1], timeout=0.3)
        assert result.reachable and not result.looks_like_mcp and result.evidence is None
    finally:
        listener.close()


# --- runner gate ---
def test_happy_path_finds_exposed_servers() -> None:
    out = _run()
    assert isinstance(out, LanOutcome) and not out.dry_run
    ids = {f.id for s in out.report.servers for f in s.findings}
    assert ids == {"LAN-EXPOSED"}
    assert all(f.dimension is Dimension.EXPOSURE for s in out.report.servers for f in s.findings)
    assert out.report.overall_grade != "A"
    assert out.audit.authorization_id == "ENG-2026-0710"
    assert out.audit.results_digest  # bound


def test_expired_manifest_is_refused() -> None:
    out = _run(now=datetime(2026, 7, 11, tzinfo=UTC))
    assert isinstance(out, LanRefusal) and "expired" in out.reason


def test_bad_manifest_is_refused() -> None:
    out = _run(manifest_bytes=b"not = = toml")
    assert isinstance(out, LanRefusal) and "invalid manifest" in out.reason


def test_signature_failure_refuses_without_probing() -> None:
    def _boom(*_a: object) -> ProbeResult:
        raise AssertionError("must not probe after signature failure")

    out = _run(verifier=lambda *_a: VerifyResult(False, "signature rejected"), prober=_boom)
    assert isinstance(out, LanRefusal) and "rejected" in out.reason


def test_public_target_is_refused() -> None:
    raw = MANIFEST.replace(b'["192.168.10.20/32"]', b'["8.8.8.8/32"]')
    out = _run(manifest_bytes=raw)
    assert isinstance(out, LanRefusal) and "public" in out.reason


def test_public_target_allowed_by_enterprise_policy() -> None:
    raw = MANIFEST.replace(b'["192.168.10.20/32"]', b'["8.8.8.8/32"]')
    out = _run(manifest_bytes=raw, public_allowlist=("8.8.8.0/24",))
    assert isinstance(out, LanOutcome)
    assert {s.bind_addr for s in out.report.servers} == {"8.8.8.8"}


def test_agent_cidr_is_refused() -> None:
    raw = MANIFEST.replace(b'["192.168.10.20/32"]', b'["192.168.10.0/30"]')
    out = _run(manifest_bytes=raw, invoker="agent")
    assert isinstance(out, LanRefusal) and "CIDR" in out.reason


def test_dry_run_sends_no_packet() -> None:
    def _boom(*_a: object) -> ProbeResult:
        raise AssertionError("dry-run must not probe")

    out = _run(dry_run=True, prober=_boom)
    assert isinstance(out, LanOutcome) and out.dry_run
    assert out.report.servers == ()
    assert out.plan_hosts == ("192.168.10.20",) and out.plan_ports == (3000, 8000)


def test_abort_switch_stops_probing() -> None:
    calls: list[str] = []

    def _spy(host: str, port: int, timeout: float) -> ProbeResult:
        calls.append(f"{host}:{port}")
        return _exposed(host, port, timeout)

    # Two hosts: abort fires on host 1's first port, and host 2 is skipped entirely.
    raw = MANIFEST.replace(b'["192.168.10.20/32"]', b'["192.168.10.20/32", "192.168.10.21/32"]')
    out = _run(manifest_bytes=raw, prober=_spy, should_abort=lambda: True)
    assert isinstance(out, LanOutcome) and out.report.servers == ()
    assert calls == []  # aborted before the first probe; second host never reached


def test_reachable_non_mcp_is_not_a_finding() -> None:
    def _open_not_mcp(host: str, port: int, timeout: float) -> ProbeResult:
        return ProbeResult(host, port, reachable=True, looks_like_mcp=False, evidence=None)

    out = _run(prober=_open_not_mcp)
    assert isinstance(out, LanOutcome) and out.report.servers == ()


def test_cooldown_is_applied_per_probe() -> None:
    slept: list[float] = []
    out = _run(sleep=slept.append)
    assert isinstance(out, LanOutcome)
    assert len(slept) == 2  # one host × two ports


def test_runtime_deadline_stops_probing() -> None:
    # A monotonic clock that jumps past the runtime ceiling on the first check.
    ticks = iter([0.0, 10_000.0, 10_000.0])
    out = _run(monotonic=lambda: next(ticks))
    assert isinstance(out, LanOutcome) and out.report.servers == ()


def test_multiple_hosts_are_each_probed() -> None:
    raw = MANIFEST.replace(b'["192.168.10.20/32"]', b'["192.168.10.20/32", "192.168.10.21/32"]')
    out = _run(manifest_bytes=raw)
    assert isinstance(out, LanOutcome)
    addrs = {s.bind_addr for s in out.report.servers}
    assert addrs == {"192.168.10.20", "192.168.10.21"}
