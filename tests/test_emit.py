"""Emit alert-layer tests (Wave 2 Feature E).

The payload builder is pure, deterministic, and REDACTED — only an 8-hex
fingerprint of a secret ever appears, never the masked preview or the raw value.
The three sinks are the only I/O; each is opt-in and swallows its own failure so
a broken alert channel can never crash the scan. The webhook sink is exercised
via injection (monkeypatching the egress primitive), never against a real host.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from mcpscan import emit as emit_mod
from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    Server,
    ServerState,
    Severity,
)
from mcpscan.drift.model import (
    ChangeType,
    Direction,
    DriftCause,
    DriftEntry,
    DriftReport,
    FactKind,
)
from mcpscan.emit import (
    EMIT_SCHEMA_VERSION,
    build_emit_payload,
    emit_ndjson,
    emit_syslog,
    emit_webhook,
)
from mcpscan.redaction import fingerprint_secret

RAW_SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123456789"


def _scan_report() -> Report:
    leaky = Finding(
        id="CRED-PLAINTEXT",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.CRITICAL,
        title="Plaintext OpenAI API key in config",
        location=Location(path="/home/jane/.mcp.json", line=4),
        remediation="Move it to a secret manager and rotate the key.",
        rationale="Plaintext credentials are trivially exfiltrated.",
        secret=fingerprint_secret(RAW_SECRET),
    )
    scoped = Finding(
        id="SCOPE-DANGEROUS-ALLOW",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title="Dangerous tool auto-allowed: 'Bash(*)'",
        location=Location(path="/home/jane/.mcp.json"),
        remediation="Remove the blanket allow.",
        rationale="Auto-approved command execution is a full RCE primitive.",
    )
    server = Server(
        id="/home/jane/.mcp.json#leaky",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=(leaky, scoped),
    )
    return Report(
        schema_version="1.1",
        servers=(server,),
        overall_grade="F",
        dimension_grades={Dimension.CREDENTIAL: "F", Dimension.TOOL_SCOPE: "C"},
    )


def _drift_report() -> DriftReport:
    return DriftReport(
        entries=(
            DriftEntry(
                change=ChangeType.ADDED,
                kind=FactKind.FINDING,
                key="/home/jane/.mcp.json#leaky::CRED-PLAINTEXT",
                summary="new finding CRED-PLAINTEXT",
                direction=Direction.REGRESSION,
                cause=DriftCause.CONFIG_DRIFT,
            ),
            DriftEntry(
                change=ChangeType.REMOVED,
                kind=FactKind.FINDING,
                key="/home/jane/.mcp.json#old::PIN-UNPINNED",
                summary="resolved finding PIN-UNPINNED",
                direction=Direction.IMPROVEMENT,
                cause=DriftCause.PROVENANCE_DRIFT,
            ),
        )
    )


# --- payload builder: shape, determinism, redaction ---
def test_scan_payload_shape_and_envelope() -> None:
    payload = build_emit_payload(
        _scan_report(),
        kind="scan",
        generated_at="2026-08-11T09:00:00+00:00",
        gate_failed=True,
        threshold="high",
    )
    assert payload["emit_schema_version"] == EMIT_SCHEMA_VERSION
    assert payload["tool"] == "ai-agentic-mcpscan"
    assert payload["kind"] == "scan"
    assert payload["generated_at"] == "2026-08-11T09:00:00+00:00"
    assert payload["gate_failed"] is True
    assert payload["threshold"] == "high"
    summary = payload["summary"]
    assert isinstance(summary, dict)
    assert summary["overall_grade"] == "F"
    assert summary["counts"]["critical"] == 1
    assert summary["counts"]["high"] == 1
    assert summary["total"] == 2
    findings = payload["findings"]
    assert isinstance(findings, list)
    # Most-severe first: the CRITICAL credential finding leads.
    assert findings[0]["id"] == "CRED-PLAINTEXT"
    assert findings[1]["id"] == "SCOPE-DANGEROUS-ALLOW"


def test_scan_payload_is_deterministic() -> None:
    kwargs: dict[str, Any] = {
        "kind": "scan",
        "generated_at": "2026-08-11T09:00:00+00:00",
        "gate_failed": False,
        "threshold": "high",
    }
    a = build_emit_payload(_scan_report(), **kwargs)
    b = build_emit_payload(_scan_report(), **kwargs)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_scan_payload_is_redacted_only_fingerprint() -> None:
    payload = build_emit_payload(
        _scan_report(), kind="scan", generated_at="t", gate_failed=True, threshold="high"
    )
    blob = json.dumps(payload)
    assert RAW_SECRET not in blob  # never the raw value
    fp = fingerprint_secret(RAW_SECRET)
    assert fp.masked not in blob  # never even the masked preview
    cred = next(f for f in payload["findings"] if f["id"] == "CRED-PLAINTEXT")
    assert cred["sha256_8"] == fp.sha256_8  # the triage handle survives
    assert "masked" not in cred and "secret" not in cred
    # A finding with no secret carries a null handle, not the key's absence.
    scoped = next(f for f in payload["findings"] if f["id"] == "SCOPE-DANGEROUS-ALLOW")
    assert scoped["sha256_8"] is None


def test_scan_finding_location_includes_line() -> None:
    payload = build_emit_payload(
        _scan_report(), kind="scan", generated_at="t", gate_failed=True, threshold="high"
    )
    cred = next(f for f in payload["findings"] if f["id"] == "CRED-PLAINTEXT")
    assert cred["location"] == "/home/jane/.mcp.json:4"


def test_payload_carries_wave2_findings_redacted() -> None:
    # Prior-agent contract: the emit payload must be able to carry the Wave 2
    # CRED-ENV (fingerprinted process-env secret) and TOKEN-STORE (no secret,
    # metadata only) findings, and stay redaction-safe end to end.
    cred_env = Finding(
        id="CRED-ENV",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.HIGH,
        title="Plaintext Anthropic API key in running process env",
        location=Location(path="process://claude[42]"),
        remediation="Pass secrets via a broker/at-runtime, not the process environment.",
        rationale="A live process holding a plaintext credential is readable/exfiltratable.",
        secret=fingerprint_secret(RAW_SECRET),
    )
    token_store = Finding(
        id="TOKEN-STORE-PERMS",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.HIGH,
        title="Token/credential store is group/world-readable",
        location=Location(path="/home/jane/.claude/.credentials.json"),
        remediation="chmod 600 the credential store.",
        rationale="A world-readable token store leaks a live credential.",
    )
    server = Server(
        id="process://claude:42",
        bind_addr=None,
        port=None,
        pid=42,
        proc_name="claude",
        state=ServerState.RUNNING,
        running=True,
        findings=(cred_env, token_store),
    )
    report = Report(
        schema_version="1.1",
        servers=(server,),
        overall_grade="F",
        dimension_grades={Dimension.CREDENTIAL: "F"},
    )
    payload = build_emit_payload(
        report, kind="scan", generated_at="t", gate_failed=True, threshold="high"
    )
    blob = json.dumps(payload)
    assert RAW_SECRET not in blob
    assert fingerprint_secret(RAW_SECRET).masked not in blob
    ids = {f["id"]: f for f in payload["findings"]}
    assert ids["CRED-ENV"]["sha256_8"] == fingerprint_secret(RAW_SECRET).sha256_8
    assert ids["TOKEN-STORE-PERMS"]["sha256_8"] is None  # no secret on this finding


def test_diff_payload_carries_entries_and_causes() -> None:
    payload = build_emit_payload(
        _drift_report(), kind="diff", generated_at="t", gate_failed=True, threshold="regression"
    )
    assert payload["kind"] == "diff"
    assert payload["emit_schema_version"] == EMIT_SCHEMA_VERSION
    summary = payload["summary"]
    assert isinstance(summary, dict)
    assert summary == {"total": 2, "regressions": 1, "improvements": 1}
    drift = payload["drift"]
    assert isinstance(drift, list)
    assert drift[0]["cause"] == "config_drift"
    assert drift[0]["direction"] == "regression"
    assert drift[1]["cause"] == "provenance_drift"
    assert "findings" not in payload  # diff has drift, not findings


# --- ndjson sink (a WRITE) ---
def test_ndjson_appends_valid_json_lines(tmp_path: Path) -> None:
    dest = tmp_path / "alerts.ndjson"
    p1 = build_emit_payload(
        _scan_report(), kind="scan", generated_at="t1", gate_failed=True, threshold="high"
    )
    p2 = build_emit_payload(
        _drift_report(), kind="diff", generated_at="t2", gate_failed=False, threshold="none"
    )
    emit_ndjson(dest, p1)
    emit_ndjson(dest, p2)
    lines = dest.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["kind"] == "scan"
    assert json.loads(lines[1])["kind"] == "diff"
    assert RAW_SECRET not in dest.read_text(encoding="utf-8")


@pytest.mark.skipif(__import__("os").name == "nt", reason="POSIX permissions only")
def test_ndjson_file_is_owner_only(tmp_path: Path) -> None:
    import stat

    dest = tmp_path / "alerts.ndjson"
    emit_ndjson(dest, {"kind": "scan"})
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


def test_ndjson_write_error_is_swallowed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A directory path can't be opened for writing -> OSError -> warned, not raised.
    emit_ndjson(tmp_path, {"kind": "scan"})
    assert "ndjson" in capsys.readouterr().err


# --- webhook sink (EGRESS) ---
def test_webhook_builds_correct_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_post(request: urllib.request.Request, timeout: float) -> None:
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["data"] = request.data
        captured["ctype"] = request.get_header("Content-type")
        captured["timeout"] = timeout

    monkeypatch.setattr(emit_mod, "_post", _fake_post)
    payload = build_emit_payload(
        _scan_report(), kind="scan", generated_at="t", gate_failed=True, threshold="high"
    )
    emit_webhook("https://alerts.example/hook", payload, timeout=3.0)
    assert captured["url"] == "https://alerts.example/hook"
    assert captured["method"] == "POST"
    assert captured["ctype"] == "application/json"
    assert captured["timeout"] == 3.0
    body = json.loads(captured["data"].decode("utf-8"))
    assert body["kind"] == "scan"
    assert RAW_SECRET not in captured["data"].decode("utf-8")


def test_webhook_network_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _boom(request: urllib.request.Request, timeout: float) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(emit_mod, "_post", _boom)
    # Must not raise; the scan proceeds.
    emit_webhook("https://alerts.example/hook", {"kind": "scan"})
    assert "webhook POST failed" in capsys.readouterr().err


def test_webhook_refuses_non_http_scheme(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _must_not_run(request: urllib.request.Request, timeout: float) -> None:
        raise AssertionError("egress must not fire for a non-HTTP(S) scheme")

    monkeypatch.setattr(emit_mod, "_post", _must_not_run)
    emit_webhook("file:///etc/passwd", {"kind": "scan"})
    assert "refused non-HTTP(S)" in capsys.readouterr().err


def test_https_only_redirect_drops_downgrade() -> None:
    handler = emit_mod._HttpsOnlyRedirect()
    req = urllib.request.Request("https://alerts.example/hook")
    from http.client import HTTPMessage

    # A redirect to plain http is refused (returns None -> not followed).
    result = handler.redirect_request(
        req, __import__("io").BytesIO(b""), 302, "Found", HTTPMessage(), "http://evil.example/x"
    )
    assert result is None


# --- syslog sink ---
def test_syslog_emits_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    class _FakeHandler:
        def __init__(self, *a: Any, **k: Any) -> None:
            events.append("open")

        def emit(self, record: Any) -> None:
            events.append(f"emit:{record.getMessage()}")

        def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(emit_mod.logging.handlers, "SysLogHandler", _FakeHandler)
    emit_syslog({"kind": "scan", "gate_failed": True})
    assert events[0] == "open"
    assert events[-1] == "close"
    emitted = next(e for e in events if e.startswith("emit:"))
    assert json.loads(emitted[len("emit:") :])["kind"] == "scan"


def test_syslog_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _explode(*a: Any, **k: Any) -> None:
        raise OSError("no syslog socket")

    monkeypatch.setattr(emit_mod.logging.handlers, "SysLogHandler", _explode)
    emit_syslog({"kind": "scan"})  # must not raise
    assert "syslog failed" in capsys.readouterr().err
