# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Objective E — make the scanner go quiet about something real.

Evasion is the attack that matters most against a scanner, because it succeeds
*silently*. A crash is loud and a leak is discoverable, but a scan that returns
grade A over a surface it never inspected leaves the operator strictly worse off
than not scanning: they now have written evidence that everything is fine.

The paths to silence, and what must close each of them:

- **Make the file unreadable.** An unparseable, oversized, or permission-denied
  config must be *reported as un-inspected* (FR-C1), not skipped. The host may
  still load a file this tool cannot.
- **Use the risk-acceptance ledger.** It suppresses gate failures by design, so
  its guardrails are load-bearing: tool-scope findings only, a named human, an
  expiry that actually expires, and no effect on the grade.
- **Tamper with the baseline.** Drift is measured against a file in the repo; if
  a rewritten baseline were trusted, "no drift" would mean nothing.
- **Poison the detection catalog.** A data-pack rewrites what counts as a secret,
  so an unverified one must be refused rather than quietly used.
- **Rely on a parser differential.** If the host and the scanner disagree about
  what a config says, the attacker picks which one is wrong.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from _xplatform import posix_only

from adversarial.corpus import (
    FAKE_ANTHROPIC_KEY,
    KITCHEN_SINK,
    deep_json,
)
from mcpscan.acceptance import LedgerEntry, apply_acceptances, load_ledgers, parse_ledger
from mcpscan.cli import main
from mcpscan.datapack import DataPackError, load_verified_datapack, parse_datapack
from mcpscan.domain import Dimension, Severity
from mcpscan.drift.baseline import BaselineError, load_baseline, render_baseline
from mcpscan.drift.snapshot import build_snapshot
from mcpscan.engine import scan
from mcpscan.lan.verify import VerifyResult

# --- 1. silence by making the file unreadable --------------------------------
UNREADABLE_SHAPES: tuple[tuple[str, str], ...] = (
    ("deeply nested", deep_json()),
    ("truncated JSON", '{"mcpServers": {"a": {"command": "sh"'),
    ("wrong root type", "[]"),
    ("binary garbage", "\x00\x01\x02\x03"),
)


@pytest.mark.parametrize(("label", "content"), UNREADABLE_SHAPES, ids=lambda v: str(v)[:20])
def test_an_unparseable_config_is_reported_not_skipped(
    label: str, content: str, tmp_path: Path
) -> None:
    """A config the scanner cannot read becomes a visible finding.

    Without this, the cheapest evasion in the tool is also the most reliable:
    corrupt the file just enough that ``json.loads`` gives up while the host —
    which is far more tolerant — still loads the servers inside it.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(content, encoding="utf-8")

    report = scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    findings = [f for s in report.servers for f in s.findings]
    assert [f.id for f in findings] == ["CONFIG-UNREADABLE"], label
    assert findings[0].location.path.endswith(".mcp.json")
    assert all(s.inspection_incomplete for s in report.servers)


@posix_only
def test_an_unreadable_config_is_reported_not_skipped(tmp_path: Path) -> None:
    """Permission-denied is the same evasion by a different route."""
    if __import__("os").geteuid() == 0:
        pytest.skip("root bypasses file permission bits")
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    config = root / ".mcp.json"
    config.write_text("{}", encoding="utf-8")
    config.chmod(0o000)
    try:
        report = scan(
            roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False
        )
        assert [f.id for s in report.servers for f in s.findings] == ["CONFIG-UNREADABLE"]
    finally:
        config.chmod(0o600)


def test_an_oversized_config_is_reported_not_skipped(tmp_path: Path) -> None:
    """A config padded past the 5 MB cap must not vanish from the report."""
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    padding = " " * (5 * 1024 * 1024 + 1)
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"hidden": {"command": "sh"}}}) + padding, encoding="utf-8"
    )
    report = scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    assert [f.id for s in report.servers for f in s.findings] == ["CONFIG-UNREADABLE"]


def test_a_missing_config_is_not_reported(tmp_path: Path) -> None:
    """The counterweight: absence is normal and must stay silent.

    Every host the tool knows about contributes candidate paths, almost none of
    which exist on a given machine. Reporting those would bury the real signal —
    which is its own kind of evasion.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    report = scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    assert report.servers == ()
    assert report.overall_grade == "A"


# --- 2. silence through the acceptance ledger --------------------------------
def _report_with(dimension: Dimension, finding_id: str, tmp_path: Path):
    """A one-finding report on a declared server, for ledger tests."""
    from mcpscan.domain import Finding, Location, Report, Server, ServerState

    finding = Finding(
        id=finding_id,
        dimension=dimension,
        severity=Severity.CRITICAL,
        title="t",
        location=Location(path=str(tmp_path / ".mcp.json")),
        remediation="fix",
        rationale="why",
    )
    server = Server(
        id=f"{tmp_path}/.mcp.json#target",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=(finding,),
    )
    return Report(schema_version="1.1", servers=(server,), overall_grade="F", dimension_grades={})


def _entry(**overrides: str) -> LedgerEntry:
    base = {
        "finding": "TOOL-AUTOAPPROVE",
        "server": "target",
        "owner": "Ada Lovelace",
        "accepted": "2026-01-01",
        "expires": "2099-01-01",
        "reason": "compensating control",
    }
    base.update(overrides)
    return LedgerEntry(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("dimension", "finding_id"),
    [
        (Dimension.CREDENTIAL, "CRED-PLAINTEXT"),
        (Dimension.EXPOSURE, "EXPOSE-BIND"),
        (Dimension.PINNING, "PIN-UNPINNED"),
    ],
)
def test_only_tool_scope_findings_can_be_accepted(
    dimension: Dimension, finding_id: str, tmp_path: Path
) -> None:
    """A ledger cannot silence a credential, exposure, or pinning finding.

    Otherwise the ledger is a universal mute button that ships in the repo: drop
    one JSON file next to the code and every CRITICAL stops failing CI.
    """
    report = _report_with(dimension, finding_id, tmp_path)
    out, warnings = apply_acceptances(report, [_entry(finding=finding_id)], today=date(2026, 6, 1))
    assert out.servers[0].findings[0].acceptance is None
    assert warnings and "cannot be risk-accepted" in warnings[0]


def test_an_expired_acceptance_gates_again(tmp_path: Path) -> None:
    """Expiry is enforced against the injected date, not silently extended."""
    report = _report_with(Dimension.TOOL_SCOPE, "TOOL-AUTOAPPROVE", tmp_path)
    out, _ = apply_acceptances(report, [_entry(expires="2026-01-01")], today=date(2026, 6, 1))
    acceptance = out.servers[0].findings[0].acceptance
    assert acceptance is not None and acceptance.expired


@pytest.mark.parametrize(
    "bad",
    [
        {"owner": ""},
        {"owner": "   "},
        {"expires": ""},
        {"expires": "not-a-date"},
        {"expires": "2026-13-45"},
        {"finding": ""},
        {"server": ""},
    ],
    ids=lambda d: str(d),
)
def test_a_ledger_entry_without_a_real_owner_or_expiry_is_refused(bad: dict[str, str]) -> None:
    """The named-human rule is what makes acceptance accountable.

    An entry with a blank owner or an unparseable expiry is not an acceptance;
    it is an anonymous, permanent mute, and it is dropped with a warning.
    """
    entry = {
        "finding": "TOOL-AUTOAPPROVE",
        "server": "s",
        "owner": "Ada",
        "expires": "2099-01-01",
        **bad,
    }
    load = parse_ledger(json.dumps({"acceptances": [entry]}), "ledger.json")
    assert load.entries == ()
    assert load.warnings


def test_acceptance_does_not_change_the_grade(tmp_path: Path) -> None:
    """Accepted findings still count against posture — only the gate relaxes.

    This is the difference between "we accepted this risk" and "this risk went
    away", and it is the property an attacker (or an over-eager team) would most
    like to blur.
    """
    from mcpscan.scoring import grade_findings

    report = _report_with(Dimension.TOOL_SCOPE, "TOOL-AUTOAPPROVE", tmp_path)
    before = grade_findings(report.servers[0].findings)
    out, _ = apply_acceptances(report, [_entry()], today=date(2026, 6, 1))
    assert grade_findings(out.servers[0].findings) == before
    assert out.overall_grade == report.overall_grade


@posix_only
def test_a_ledger_symlinked_outside_the_root_is_refused(tmp_path: Path) -> None:
    """The ledger is read through ``io_safe``, so it cannot pull in a file
    from outside the scanned root."""
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps({"acceptances": []}), encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcpscan-accept.json").symlink_to(outside)

    load = load_ledgers([root])
    assert load.entries == ()
    assert load.warnings and "unreadable acceptance ledger" in load.warnings[0]


def test_a_hostile_ledger_cannot_crash_the_scan(tmp_path: Path) -> None:
    """Every malformed ledger shape degrades to a warning."""
    for content in ("{not json", "[]", '{"acceptances": {}}', deep_json(), KITCHEN_SINK):
        load = parse_ledger(content, "ledger.json")
        assert load.entries == ()
        assert load.warnings


def test_the_exit_gate_counts_an_unaccepted_finding(tmp_path: Path, capsys) -> None:
    """End-to-end: a hostile repo exits non-zero, and a ledger cannot mute a
    CRITICAL credential finding."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"leaky": {"command": "sh", "env": {"API_KEY": FAKE_ANTHROPIC_KEY}}}}
        ),
        encoding="utf-8",
    )
    (root / ".mcpscan-accept.json").write_text(
        json.dumps(
            {
                "acceptances": [
                    {
                        "finding": "CRED-PLAINTEXT",
                        "server": "leaky",
                        "owner": "Ada",
                        "expires": "2099-01-01",
                        "reason": "nope",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", "--root", str(root), "--fail-on", "critical"])
    assert code == 1
    assert "cannot be risk-accepted" in capsys.readouterr().err


# --- 3. silence by rewriting the baseline ------------------------------------
def test_an_edited_baseline_fails_its_integrity_check(tmp_path: Path) -> None:
    """Drift is only meaningful if the baseline is the one that was written."""
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg"]}}}),
        encoding="utf-8",
    )
    report = scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    text = render_baseline(build_snapshot(report), created_at="2026-01-01")

    load_baseline(text)  # the untampered baseline loads

    tampered = json.loads(text)
    tampered["facts"] = []  # "there was never anything here"
    with pytest.raises(BaselineError, match="integrity"):
        load_baseline(json.dumps(tampered))


def test_a_baseline_with_a_recomputed_digest_is_documented_as_trusted(tmp_path: Path) -> None:
    """Scope statement: the digest detects *corruption*, not a motivated editor.

    It is a plain hash of the facts, not a MAC over a key the attacker lacks, so
    anyone who can rewrite the file can recompute it. Pinning that here keeps the
    limitation explicit — the baseline is trusted-at-rest input, and a repo where
    an attacker can rewrite committed files has a bigger problem than drift.
    """
    from mcpscan.drift.snapshot import snapshot_digest

    snapshot = build_snapshot(
        scan(roots=[tmp_path], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    )
    text = render_baseline(snapshot, created_at="2026-01-01")
    forged = json.loads(text)
    forged["facts"] = []
    forged["digest"] = snapshot_digest(load_baseline(json.dumps(forged), verify_digest=False))
    load_baseline(json.dumps(forged))  # accepted — by design, and documented


# --- 4. silence by poisoning the detection catalog ---------------------------
def _refusing_verifier(*_args: object) -> VerifyResult:
    return VerifyResult(ok=False, detail="signature does not verify")


def _accepting_verifier(*_args: object) -> VerifyResult:
    return VerifyResult(ok=True, detail="ok")


def test_an_unverified_datapack_is_refused(tmp_path: Path) -> None:
    """Verify-or-refuse: a pack that fails its signature is never parsed.

    A data-pack defines what counts as a secret. An attacker who could install
    one would not need to hide anything — they would redefine "secret" to match
    nothing and let the scan pass honestly.
    """
    pack = tmp_path / "pack.json"
    pack.write_text('{"schema_version": "1.0"}', encoding="utf-8")
    result = load_verified_datapack(
        pack,
        tmp_path / "pack.sig",
        tmp_path / "signers",
        operator="op",
        verifier=_refusing_verifier,
    )
    assert isinstance(result, DataPackError)
    assert "refused" in result.message


@pytest.mark.parametrize("scheme", ["SSH", "ed25519 ", "rsa", "", "none", "ecdsa"])
def test_an_unknown_signature_scheme_is_refused(scheme: str, tmp_path: Path) -> None:
    """Scheme confusion fails closed — including on case and whitespace."""
    result = load_verified_datapack(
        tmp_path / "pack.json",
        tmp_path / "sig",
        tmp_path / "signers",
        operator="op",
        scheme=scheme,
        verifier=_accepting_verifier,
        pack_bytes=b"{}",
    )
    assert isinstance(result, DataPackError)
    assert "unsupported signature scheme" in result.message


def test_a_verified_pack_binds_to_the_bytes_that_were_checked(tmp_path: Path) -> None:
    """The signature covers exactly the bytes the caller goes on to install.

    Passing ``pack_bytes`` removes the second read a concurrent write could
    diverge from — the classic time-of-check/time-of-use swap.
    """
    seen: list[bytes] = []

    def recording_verifier(payload: bytes, *_rest: object) -> VerifyResult:
        seen.append(payload)
        return VerifyResult(ok=True, detail="ok")

    pack = tmp_path / "pack.json"
    pack.write_text("ON DISK — DIFFERENT", encoding="utf-8")
    checked = json.dumps(
        {
            "schema_version": "1.0",
            "provider_patterns": [{"label": "x", "pattern": "sk-[A-Z]{10}"}],
            "secret_name_pattern": "TOKEN",
            "entropy_threshold": 3.5,
            "min_entropy_len": 20,
            "agent_markers": ["mcp"],
            "token_store_templates": [],
        }
    ).encode("utf-8")

    load_verified_datapack(
        pack,
        tmp_path / "sig",
        tmp_path / "signers",
        operator="op",
        verifier=recording_verifier,
        pack_bytes=checked,
    )
    assert seen == [checked]


def test_a_malformed_pack_is_refused_even_with_a_valid_signature(tmp_path: Path) -> None:
    """A signature attests to bytes, not to sanity — validation still runs."""
    for body in (b"not json", deep_json().encode(), b"[]", b"\xff\xfe"):
        result = load_verified_datapack(
            tmp_path / "pack.json",
            tmp_path / "sig",
            tmp_path / "signers",
            operator="op",
            verifier=_accepting_verifier,
            pack_bytes=body,
        )
        assert isinstance(result, DataPackError)


def test_a_pack_that_would_weaken_detection_still_parses_and_that_is_the_trust_boundary(
    tmp_path: Path,
) -> None:
    """Scope statement: a *signed* pack is trusted to define detection.

    A pack with no provider patterns and an unreachable entropy threshold detects
    nothing. That is accepted by design — the control is the signature and the
    owner-only store, not content inspection. Pinning it here makes the boundary
    a deliberate, reviewable decision rather than an oversight, and keeps the
    ``update-datapack`` verification path load-bearing.
    """
    weakened = parse_datapack(
        json.dumps(
            {
                "schema_version": "1.0",
                "provider_patterns": [],
                "secret_name_pattern": "MATCHES_NOTHING_XYZZY",
                "entropy_threshold": 99.0,
                "min_entropy_len": 100000,
                "agent_markers": ["mcp"],
                "token_store_templates": [],
            }
        )
    )
    assert not isinstance(weakened, DataPackError)
    assert weakened.provider_patterns == ()


def test_a_corrupt_local_store_falls_back_to_the_builtin_pack(tmp_path: Path) -> None:
    """Fail-safe, not fail-open: a broken store never weakens a scan below the
    built-in catalog."""
    from mcpscan.datapack import builtin_datapack, load_local_datapack

    store = tmp_path / "datapack.json"
    for content in ("{not json", deep_json(), '{"schema_version": ""}'):
        store.write_text(content, encoding="utf-8")
        assert load_local_datapack(store) is None
    assert builtin_datapack().provider_patterns  # the fallback still detects


# --- 5. silence through a parser differential --------------------------------
def test_duplicate_server_keys_resolve_the_way_json_does(tmp_path: Path) -> None:
    """A duplicated key must not make a server disappear entirely.

    JSON's last-key-wins is what hosts do too, so the scanner matching it is
    correct — what would be wrong is dropping *both* declarations and reporting
    nothing.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    duplicated = (
        '{"mcpServers": {'
        '"a": {"command": "clean"}, '
        '"a": {"command": "sh", "env": {"API_KEY": "' + FAKE_ANTHROPIC_KEY + '"}}'
        "}}"
    )
    assert json.loads(duplicated)["mcpServers"]["a"]["command"] == "sh"  # last wins
    (root / ".mcp.json").write_text(duplicated, encoding="utf-8")
    report = scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    ids = [f.id for s in report.servers for f in s.findings]
    assert "CRED-PLAINTEXT" in ids  # the surviving (last) declaration is audited


def test_a_secret_hidden_behind_jsonc_comments_is_still_found(tmp_path: Path) -> None:
    """Comment syntax must not become a place to hide a live declaration.

    VS Code reads JSONC, so a server "commented out" with a construct the editor
    does not treat as a comment is still live — the scanner strips comments the
    same way the editor does, and audits what remains.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".vscode").mkdir()
    (root / ".vscode" / "mcp.json").write_text(
        "{\n"
        '  // "servers": {"decoy": {"command": "true"}},\n'
        '  "servers": {\n'
        '    "real": {"command": "sh", "env": {"API_KEY": "' + FAKE_ANTHROPIC_KEY + '"}},\n'
        "  },\n"
        "}\n",
        encoding="utf-8",
    )
    report = scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    ids = [f.id for s in report.servers for f in s.findings]
    assert "CRED-PLAINTEXT" in ids
    assert not any(s.id.endswith("#decoy") for s in report.servers)
