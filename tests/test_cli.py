"""CLI wiring tests (help, scan summary, exit codes, report writing, warnings)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

import mcpscan.engine as engine_mod
from mcpscan.cli import main
from mcpscan.domain import Finding, Report, Severity


def test_no_command_prints_help_and_succeeds(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([])
    assert rc == 0
    assert "mcpscan" in capsys.readouterr().out


def test_scan_clean_returns_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    rc = main(["scan"])
    assert rc == 0
    assert "posture: A" in capsys.readouterr().out


def test_scan_with_critical_returns_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report(make_finding()))
    assert main(["scan"]) == 1


def test_fail_on_threshold_respected(
    monkeypatch: pytest.MonkeyPatch,
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
) -> None:
    # A MEDIUM finding is non-blocking at the default 'high' threshold but
    # blocking when --fail-on is lowered to 'medium'.
    medium = make_finding(id="M", severity=Severity.MEDIUM)
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report(medium))
    assert main(["scan"]) == 0
    assert main(["scan", "--fail-on", "medium"]) == 1


def test_writes_json_and_html_reports(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    rc = main(["scan", "--json", str(json_path), "--html", str(html_path)])
    assert rc == 0
    assert isinstance(json.loads(json_path.read_text(encoding="utf-8")), dict)
    assert html_path.exists() and "<html" in html_path.read_text(encoding="utf-8").lower()
    err = capsys.readouterr().err
    assert "wrote JSON report" in err
    assert "wrote HTML report" in err


def test_writes_sarif_report(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report(make_finding()))
    sarif_path = tmp_path / "results.sarif"
    # A critical finding still writes SARIF before the non-zero exit.
    rc = main(["scan", "--sarif", str(sarif_path), "--fail-on", "critical"])
    assert rc == 1
    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"], "expected at least one SARIF result"
    assert "wrote SARIF report" in capsys.readouterr().err


def test_fix_removes_dangerous_grant_and_backs_up(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    # End-to-end: a project .mcp.json with an auto-allowed Bash(*) is remediated
    # in place, a backup is written, and a re-scan finds the tool-scope issue gone.
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(
        json.dumps({"mcpServers": {}, "permissions": {"allow": ["Read", "Bash(*)"]}}),
        encoding="utf-8",
    )
    rc = main(["scan", "--root", str(tmp_path), "--fix", "--fail-on", "low"])
    # Exit code reflects the pre-fix scan (a HIGH finding was present).
    assert rc == 1
    assert (tmp_path / ".mcp.json.mcpscan.bak").exists()
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["permissions"]["allow"] == ["Read"]  # Bash(*) removed
    err = capsys.readouterr().err
    assert "--fix modifies config files" in err
    assert "applied 1 fix" in err


def test_no_fix_flag_never_writes(tmp_path: Path) -> None:
    # Advise-only preserved: without --fix, the config is byte-for-byte untouched
    # and no backup is created.
    cfg = tmp_path / ".mcp.json"
    original = json.dumps({"mcpServers": {}, "permissions": {"allow": ["Bash(*)"]}})
    cfg.write_text(original, encoding="utf-8")
    main(["scan", "--root", str(tmp_path)])
    assert cfg.read_text(encoding="utf-8") == original
    assert not (tmp_path / ".mcp.json.mcpscan.bak").exists()


def test_fix_with_nothing_to_do_reports_cleanly(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {}, "permissions": {"allow": ["Read"]}}), "utf-8")
    main(["scan", "--root", str(tmp_path), "--fix"])
    assert "no auto-fixable tool-scope findings." in capsys.readouterr().err
    assert not (tmp_path / ".mcp.json.mcpscan.bak").exists()


def test_show_secrets_emits_warning(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    main(["scan", "--show-secrets"])
    assert "--show-secrets" in capsys.readouterr().err


def test_online_emits_note(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    main(["scan", "--online"])
    assert "api.osv.dev" in capsys.readouterr().err


# --- lan command wiring ---
_LAN_ED25519 = b"""
authorization_id = "ENG-2026-0710"
operator = "op@example.com"
expires_at = 2030-01-01T00:00:00Z
targets = ["192.168.10.20/32"]
ports = [3000]
[signature]
scheme = "ed25519"
"""


def test_lan_requires_manifest_and_invoker(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lan"]) == 2
    assert "requires --manifest and --invoker" in capsys.readouterr().err


def test_lan_unreadable_manifest_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    assert main(["lan", "--manifest", str(missing), "--invoker", "human"]) == 2
    assert "cannot read manifest" in capsys.readouterr().err


def test_lan_ed25519_without_signature_files_is_refused(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # Real run through the CLI: without --allowed-signers the ed25519 scheme is
    # refused before any probe (the signature files are required).
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    assert main(["lan", "--manifest", str(manifest), "--invoker", "human"]) == 2
    err = capsys.readouterr().err
    assert "refused:" in err and "requires" in err


def test_lan_success_prints_report_and_audit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
    tmp_path: Path,
) -> None:
    from mcpscan.domain import Dimension
    from mcpscan.lan.audit import AuditRecord
    from mcpscan.lan.runner import LanOutcome

    finding = make_finding(id="LAN-EXPOSED", severity=Severity.HIGH, dimension=Dimension.EXPOSURE)
    audit = AuditRecord(
        manifest_sha256="a" * 64,
        authorization_id="ENG-42",
        operator="op@example.com",
        tool_version="0.6.0",
        invoker="human",
        utc_timestamp="2026-07-10T09:00:00Z",
        argv=("mcpscan", "lan"),
        resolved_targets=("192.168.10.20",),
        results_digest="d" * 64,
    )
    outcome = LanOutcome(
        report=make_report(finding),
        audit=audit,
        dry_run=False,
        plan_hosts=("192.168.10.20",),
        plan_ports=(3000,),
    )
    monkeypatch.setattr("mcpscan.lan.run_lan", lambda **_: outcome)
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    out_json = tmp_path / "lan.json"

    rc = main(["lan", "--manifest", str(manifest), "--invoker", "human", "--json", str(out_json)])
    assert rc == 1  # a HIGH finding is blocking at the default threshold
    err = capsys.readouterr().err
    assert "authorized run ENG-42" in err
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["audit"]["authorization_id"] == "ENG-42"
    assert payload["report"]["servers"]


def test_lan_dry_run_sends_no_packet(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    tmp_path: Path,
) -> None:
    from mcpscan.lan.audit import AuditRecord
    from mcpscan.lan.runner import LanOutcome

    audit = AuditRecord(
        manifest_sha256="a" * 64,
        authorization_id="ENG-42",
        operator="op@example.com",
        tool_version="0.6.0",
        invoker="human",
        utc_timestamp="2026-07-10T09:00:00Z",
        argv=("mcpscan", "lan"),
        resolved_targets=("192.168.10.20",),
        results_digest="d" * 64,
    )
    outcome = LanOutcome(
        report=make_report(),
        audit=audit,
        dry_run=True,
        plan_hosts=("192.168.10.20",),
        plan_ports=(3000, 8000),
    )
    monkeypatch.setattr("mcpscan.lan.run_lan", lambda **_: outcome)
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    assert main(["lan", "--manifest", str(manifest), "--invoker", "human", "--dry-run"]) == 0
    err = capsys.readouterr().err
    assert "[dry-run]" in err and "no packets sent" in err


def test_lan_invalid_enterprise_policy_errors(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    policy = tmp_path / "policy.toml"
    policy.write_text("not = = toml", encoding="utf-8")
    rc = main(
        [
            "lan",
            "--manifest",
            str(manifest),
            "--invoker",
            "human",
            "--enterprise-policy",
            str(policy),
        ]
    )
    assert rc == 2
    assert "invalid enterprise policy" in capsys.readouterr().err


def test_lan_unreadable_enterprise_policy_errors(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    rc = main(
        [
            "lan",
            "--manifest",
            str(manifest),
            "--invoker",
            "human",
            "--enterprise-policy",
            str(tmp_path / "missing.toml"),
        ]
    )
    assert rc == 2
    assert "cannot read enterprise policy" in capsys.readouterr().err


def test_lan_valid_policy_is_loaded_then_run(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # A valid policy loads (exercising the success path), then the ed25519
    # manifest is refused at verification — proving the policy wiring is reached.
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    policy = tmp_path / "policy.toml"
    policy.write_text('public_targets = ["203.0.113.0/28"]', encoding="utf-8")
    rc = main(
        [
            "lan",
            "--manifest",
            str(manifest),
            "--invoker",
            "human",
            "--enterprise-policy",
            str(policy),
        ]
    )
    assert rc == 2
    assert "refused:" in capsys.readouterr().err  # reached run_lan past policy load


def test_lan_sarif_emits_logical_locations(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # LAN + SARIF now emits logical locations (ADR-16), not a fail-closed refusal.
    from mcpscan.domain import (
        Dimension,
        Finding,
        Location,
        Report,
        Server,
        ServerState,
    )
    from mcpscan.domain import (
        Severity as Sev,
    )
    from mcpscan.lan.audit import AuditRecord
    from mcpscan.lan.runner import LanOutcome

    finding = Finding(
        id="LAN-EXPOSED",
        dimension=Dimension.EXPOSURE,
        severity=Sev.HIGH,
        title="MCP server reachable across the network at 192.168.10.20:3000",
        location=Location(path="192.168.10.20:3000"),
        remediation="Bind to loopback.",
        rationale="Reachable across the LAN.",
    )
    server = Server(
        id="lan://192.168.10.20:3000",
        bind_addr="192.168.10.20",
        port=3000,
        pid=None,
        proc_name=None,
        state=ServerState.RUNNING,
        running=True,
        findings=(finding,),
    )
    report = Report(
        schema_version="1.0",
        servers=(server,),
        overall_grade="C",
        dimension_grades={Dimension.EXPOSURE: "C"},
    )
    audit = AuditRecord(
        manifest_sha256="a" * 64,
        authorization_id="ENG-42",
        operator="op@example.com",
        tool_version="1.0.0",
        invoker="human",
        utc_timestamp="2026-07-10T09:00:00Z",
        argv=("mcpscan", "lan"),
        resolved_targets=("192.168.10.20",),
        results_digest="d" * 64,
    )
    outcome = LanOutcome(
        report=report, audit=audit, dry_run=False, plan_hosts=("192.168.10.20",), plan_ports=(3000,)
    )
    monkeypatch.setattr("mcpscan.lan.run_lan", lambda **_: outcome)
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    dest = tmp_path / "lan.sarif"

    rc = main(["lan", "--manifest", str(manifest), "--invoker", "human", "--sarif", str(dest)])
    assert rc == 1  # HIGH finding is blocking
    payload = json.loads(dest.read_text(encoding="utf-8"))
    result = payload["runs"][0]["results"][0]
    loc = result["locations"][0]
    assert "physicalLocation" not in loc  # not a synthetic file
    logical = loc["logicalLocations"][0]
    assert logical["name"] == "192.168.10.20:3000"
    assert logical["fullyQualifiedName"] == "lan://192.168.10.20:3000"
    assert logical["kind"] == "resource"


# --- inventory command (Tier 1) ---
def test_inventory_prints_assets_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import mcpscan.inventory.collect as collect_mod
    from mcpscan.discovery.sockets import EnumerationResult, ListeningSocket

    monkeypatch.setattr(
        collect_mod,
        "enumerate_listening",
        lambda: EnumerationResult(
            sockets=(ListeningSocket(ip="127.0.0.1", port=11434, pid=7, proc_name="ollama"),)
        ),
    )
    rc = main(["inventory", "--root", str(tmp_path), "--no-probe"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "inventory" in out and "Ollama" in out


def test_inventory_writes_json_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import mcpscan.inventory.collect as collect_mod
    from mcpscan.discovery.sockets import EnumerationResult

    monkeypatch.setattr(collect_mod, "enumerate_listening", lambda: EnumerationResult(sockets=()))
    dest = tmp_path / "inv.json"
    rc = main(["inventory", "--root", str(tmp_path), "--no-probe", "--json", str(dest)])
    assert rc == 0
    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert isinstance(payload["assets"], list)


def test_inventory_is_always_exit_zero_even_with_assets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Inventory observes; it is not a CI gate like scan's --fail-on.
    import mcpscan.inventory.collect as collect_mod
    from mcpscan.discovery.sockets import EnumerationResult, ListeningSocket

    monkeypatch.setattr(
        collect_mod,
        "enumerate_listening",
        lambda: EnumerationResult(
            sockets=(ListeningSocket(ip="0.0.0.0", port=6333, pid=1, proc_name="qdrant"),)
        ),
    )
    assert main(["inventory", "--root", str(tmp_path), "--no-probe"]) == 0


# --- atlas command (Tier 2) ---
def test_atlas_matrix_needs_no_scan(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["atlas", "--matrix"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "atlas reference matrix" in out and "CRED-PLAINTEXT" in out


def test_atlas_annotates_scan_findings(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
) -> None:
    monkeypatch.setattr(
        engine_mod, "scan", lambda **_: make_report(make_finding(id="CRED-PLAINTEXT"))
    )
    rc = main(["atlas"])
    assert rc == 1  # same --fail-on gate as scan (critical >= high)
    out = capsys.readouterr().out
    assert "T1552.001" in out


def test_atlas_writes_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    make_report: Callable[..., Report],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    dest = tmp_path / "atlas.json"
    rc = main(["atlas", "--json", str(dest)])
    assert rc == 0
    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert "matrix" in payload and payload["findings"] == []


# --- trust command (Tier 4) ---
def test_trust_reports_score_and_relationships(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "db": {
                        "command": "npx",
                        "args": ["pg-mcp"],
                        "env": {"PGPASSWORD": "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX0123456789"},
                        "autoApprove": ["run_command"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    rc = main(["trust", "--root", str(tmp_path)])
    assert rc == 0  # no --min-grade gate
    out = capsys.readouterr().out
    assert "agent trust" in out and "PRIVILEGED-SECRET-HOLDER" in out


def test_trust_min_grade_gate(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "db": {
                        "command": "npx",
                        "args": ["pg-mcp"],
                        "env": {"PGPASSWORD": "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX0123456789"},
                        "autoApprove": ["run_command"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    # This tool grades well below B -> the gate fails.
    assert main(["trust", "--root", str(tmp_path), "--min-grade", "B"]) == 1


def test_trust_clean_config_passes_gate_and_writes_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"safe": {"command": "npx", "args": ["x@1.2.3"]}}}),
        encoding="utf-8",
    )
    dest = tmp_path / "trust.json"
    rc = main(["trust", "--root", str(tmp_path), "--min-grade", "A", "--json", str(dest)])
    assert rc == 0
    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert payload["profiles"][0]["score"] == 100


# --- baseline / diff commands (Tier 5) ---
def test_baseline_writes_snapshot_then_diff_is_clean(tmp_path: Path) -> None:
    # A project with an exposed tool-scope grant produces findings; baseline then
    # diff against the unchanged tree reports no drift.
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(
        json.dumps({"mcpServers": {}, "permissions": {"allow": ["Bash(*)"]}}), encoding="utf-8"
    )
    base = tmp_path / "baseline.json"
    rc = main(["baseline", "--root", str(tmp_path), "--no-inventory", "--out", str(base)])
    assert rc == 0
    payload = json.loads(base.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0" and "digest" in payload

    rc = main(["diff", "--root", str(tmp_path), "--no-inventory", "--baseline", str(base)])
    assert rc == 0  # no drift, no regression


def test_diff_flags_regression_when_finding_appears(tmp_path: Path) -> None:
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {}, "permissions": {"allow": ["Read"]}}), "utf-8")
    base = tmp_path / "baseline.json"
    assert main(["baseline", "--root", str(tmp_path), "--no-inventory", "--out", str(base)]) == 0

    # Introduce a dangerous grant -> a new finding -> a regression.
    cfg.write_text(
        json.dumps({"mcpServers": {}, "permissions": {"allow": ["Bash(*)"]}}), encoding="utf-8"
    )
    rc = main(
        [
            "diff",
            "--root",
            str(tmp_path),
            "--no-inventory",
            "--baseline",
            str(base),
            "--fail-on-regression",
        ]
    )
    assert rc == 1  # regression -> non-zero under the gate


def test_diff_requires_baseline(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["diff"]) == 2
    assert "requires --baseline" in capsys.readouterr().err


def test_diff_unreadable_baseline_errors(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert main(["diff", "--baseline", str(tmp_path / "nope.json")]) == 2
    assert "cannot read baseline" in capsys.readouterr().err


def test_diff_corrupt_baseline_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    assert main(["diff", "--baseline", str(bad)]) == 2
    assert "malformed" in capsys.readouterr().err


def test_baseline_to_stdout_when_no_out(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    rc = main(["baseline", "--root", str(tmp_path), "--no-inventory"])
    assert rc == 0
    assert '"schema_version"' in capsys.readouterr().out


def test_baseline_with_inventory_and_diff_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Exercise the default (inventory-included) baseline path and diff --json.
    import mcpscan.inventory.collect as collect_mod
    from mcpscan.discovery.sockets import EnumerationResult

    monkeypatch.setattr(collect_mod, "enumerate_listening", lambda: EnumerationResult(sockets=()))
    base = tmp_path / "baseline.json"
    assert main(["baseline", "--root", str(tmp_path), "--no-probe", "--out", str(base)]) == 0

    drift_json = tmp_path / "drift.json"
    rc = main(
        [
            "diff",
            "--root",
            str(tmp_path),
            "--no-probe",
            "--baseline",
            str(base),
            "--json",
            str(drift_json),
        ]
    )
    assert rc == 0
    payload = json.loads(drift_json.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 0  # unchanged posture
