"""Renderer tests: JSON determinism, HTML offline-safety, redaction, paths, perms."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

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
from mcpscan.redaction import fingerprint_secret
from mcpscan.report import RenderOptions, display_path
from mcpscan.report.html import render_html
from mcpscan.report.json_report import render_json
from mcpscan.report.terminal import render_terminal
from mcpscan.report.writer import write_report

RAW_SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123456789"


def _report(home: str = "/home/jane") -> Report:
    finding = Finding(
        id="CRED-PLAINTEXT",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.CRITICAL,
        title="Plaintext OpenAI API key in config",
        location=Location(path=f"{home}/.mcp.json", line=4),
        remediation="Move it to a secret manager and rotate the key.",
        rationale="Plaintext credentials are trivially exfiltrated.",
        secret=fingerprint_secret(RAW_SECRET),
    )
    server = Server(
        id=f"{home}/.mcp.json#leaky",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=(finding,),
    )
    return Report(
        schema_version="1.0",
        servers=(server,),
        overall_grade="F",
        dimension_grades={Dimension.CREDENTIAL: "F", Dimension.EXPOSURE: "A"},
    )


# --- JSON (T-302) ---
def test_json_is_deterministic() -> None:
    r = _report()
    assert render_json(r) == render_json(r)  # byte-stable


def test_json_never_contains_raw_secret() -> None:
    out = render_json(_report(), RenderOptions(home="/home/jane"))
    assert RAW_SECRET not in out
    data = json.loads(out)
    secret = data["servers"][0]["findings"][0]["secret"]
    assert "masked" not in secret  # redacted by default
    assert secret["length"] == len(RAW_SECRET)


def test_json_show_secrets_adds_masked_only() -> None:
    out = render_json(_report(), RenderOptions(show_secrets=True, home="/home/jane"))
    secret = json.loads(out)["servers"][0]["findings"][0]["secret"]
    assert "masked" in secret
    assert RAW_SECRET not in out  # masked, never raw


def test_json_reuse_findings_never_contain_raw_secret() -> None:
    # Blast-radius corpus (Wave 1 Feature C): CRED-REUSE findings carry the shared
    # fingerprint's triage handle but must stay redaction-safe end to end.
    from dataclasses import replace

    from mcpscan.checks.secrets import check_secret_reuse

    leaky = _report().servers[0]
    twin = replace(
        leaky,
        id="/home/jane/.cursor/mcp.json#twin",
        findings=(
            replace(
                leaky.findings[0],
                location=Location(path="/home/jane/.cursor/mcp.json", line=7),
            ),
        ),
    )
    additions = check_secret_reuse([leaky, twin])
    servers = tuple(replace(s, findings=s.findings + tuple(additions[s.id])) for s in (leaky, twin))
    report = Report(
        schema_version="1.0",
        servers=servers,
        overall_grade="F",
        dimension_grades={Dimension.CREDENTIAL: "F"},
    )
    out = render_json(report, RenderOptions(home="/home/jane"))
    assert RAW_SECRET not in out
    data = json.loads(out)
    reuse = [f for s in data["servers"] for f in s["findings"] if f["id"] == "CRED-REUSE"]
    assert len(reuse) == 2
    for entry in reuse:
        assert "masked" not in entry["secret"]  # redacted by default
        assert entry["secret"]["sha256_8"]  # the operator triage handle survives


# --- path privacy (T-306) ---
def test_display_path_relativizes_home() -> None:
    opts = RenderOptions(home="/home/jane")
    assert display_path("/home/jane/.mcp.json", opts) == "~/.mcp.json"
    assert display_path("/etc/other", opts) == "/etc/other"


def test_display_path_home_itself_is_tilde() -> None:
    # The home directory rendered on its own collapses to a bare "~".
    opts = RenderOptions(home="/home/jane")
    assert display_path("/home/jane", opts) == "~"


def test_display_path_is_separator_agnostic() -> None:
    # Must work regardless of the OS rendering the report (Windows CI etc.).
    win = RenderOptions(home="C:\\Users\\jane")
    assert display_path("C:\\Users\\jane\\.mcp.json", win) == "~\\.mcp.json"
    posix = RenderOptions(home="/home/jane")
    assert display_path("/home/jane/.mcp.json", posix) == "~/.mcp.json"


def test_absolute_paths_opt_out() -> None:
    opts = RenderOptions(home="/home/jane", absolute_paths=True)
    assert display_path("/home/jane/.mcp.json", opts) == "/home/jane/.mcp.json"


def test_json_path_is_relativized_by_default() -> None:
    out = render_json(_report(), RenderOptions(home="/home/jane"))
    path = json.loads(out)["servers"][0]["findings"][0]["location"]["path"]
    assert path == "~/.mcp.json"


# --- HTML (T-303) ---
def test_html_makes_no_external_references() -> None:
    html = render_html(_report(), RenderOptions(home="/home/jane"))
    lowered = html.lower()
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "cdn" not in lowered
    assert "src=" not in lowered  # no external images/scripts
    assert "Plaintext OpenAI API key" in html
    assert RAW_SECRET not in html


def test_html_escapes_and_grades() -> None:
    html = render_html(_report())
    assert "grade-F" in html


# --- terminal (T-301) ---
def test_terminal_redacts_by_default() -> None:
    out = render_terminal(_report(), RenderOptions(home="/home/jane"))
    assert "[redacted" in out
    assert RAW_SECRET not in out
    assert "overall posture: F" in out


def test_terminal_clean_report() -> None:
    clean = Report(schema_version="1.0", servers=(), overall_grade="A", dimension_grades={})
    assert "No findings" in render_terminal(clean)


def test_terminal_skips_servers_without_findings() -> None:
    # A discovered-but-clean server is present in the report yet must not print a
    # section of its own — only the flagged server is rendered.
    clean_server = Server(
        id="/home/jane/.mcp.json#tidy",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=(),
    )
    flagged = _report().servers[0]
    report = Report(
        schema_version="1.0",
        servers=(clean_server, flagged),
        overall_grade="F",
        dimension_grades={Dimension.CREDENTIAL: "F"},
    )
    out = render_terminal(report, RenderOptions(home="/home/jane"))
    assert "#tidy" not in out  # the clean server is skipped
    assert "#leaky" in out  # the flagged server is rendered


# --- acceptance annotations (Wave 1 Feature D) ---
def _accepted_report(*, expired: bool = False) -> Report:
    from dataclasses import replace

    from mcpscan.domain import Acceptance

    acceptance = Acceptance(
        owner="Jane Doe",
        accepted="2026-08-11",
        expires="2026-11-11",
        reason="CI runner is ephemeral",
        expired=expired,
    )
    scoped = Finding(
        id="SCOPE-DANGEROUS-ALLOW",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title="Dangerous tool auto-allowed: 'Bash(*)'",
        location=Location(path="/home/jane/.mcp.json"),
        remediation="Remove the blanket allow.",
        rationale="Auto-approved command execution is a full RCE primitive.",
        acceptance=acceptance,
    )
    base = _report()
    server = replace(base.servers[0], findings=(scoped, *base.servers[0].findings))
    return replace(base, servers=(server,))


def test_json_acceptance_object_present_only_when_set() -> None:
    out = render_json(_accepted_report(), RenderOptions(home="/home/jane"))
    findings = {f["id"]: f for f in json.loads(out)["servers"][0]["findings"]}
    acceptance = findings["SCOPE-DANGEROUS-ALLOW"]["acceptance"]
    assert acceptance["owner"] == "Jane Doe"
    assert acceptance["expires"] == "2026-11-11"
    assert acceptance["expired"] is False
    assert "acceptance" not in findings["CRED-PLAINTEXT"]  # optional key


def test_terminal_annotates_acceptance_and_states_gate_vs_grade() -> None:
    out = render_terminal(_accepted_report(), RenderOptions(home="/home/jane"))
    assert "[ACCEPTED until 2026-11-11 by Jane Doe] — CI runner is ephemeral" in out
    assert "accepted findings still lower the grade" in out


def test_terminal_expired_acceptance_is_loud() -> None:
    out = render_terminal(_accepted_report(expired=True), RenderOptions(home="/home/jane"))
    assert "acceptance EXPIRED (Jane Doe, expired 2026-11-11)" in out
    assert "[ACCEPTED" not in out


def test_html_shows_acceptance_annotation() -> None:
    html = render_html(_accepted_report(), RenderOptions(home="/home/jane"))
    assert "ACCEPTED until 2026-11-11 by Jane Doe" in html


# --- writer perms (T-305) ---
@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_write_report_is_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    write_report(target, '{"ok": true}')
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600
    assert target.read_text() == '{"ok": true}'


def test_write_report_overwrites(tmp_path: Path) -> None:
    target = tmp_path / "r.json"
    write_report(target, "first")
    write_report(target, "second")
    assert target.read_text() == "second"
