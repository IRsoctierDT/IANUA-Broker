# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Objective D — get the scanner to hand back the secrets it found.

The tool's worst possible failure is not missing a secret; it is **printing
one**. It reads credentials by design, then writes reports, alert payloads,
baselines, and SARIF into places secrets must never reach — a CI log, a webhook,
a shared HTML file, a git-committed baseline.

Architecture refinement R1 makes that a structural property rather than a habit:
a raw value is reduced to a :class:`~mcpscan.domain.SecretFingerprint` at the
moment of detection, and no domain type has a field that can hold one. This
module attacks that boundary from the outside — detect a secret through every
input surface, then sweep every output surface for the raw value — so the
guarantee is tested end to end rather than assumed from the type definitions.

The sweep runs over a corpus of secret shapes on purpose: a secret containing
regex metacharacters, a bidi override, or an ANSI escape is still a secret, and
a leak that only appears for one shape is still a leak.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _xplatform import posix_only

from adversarial.corpus import (
    ANSI_CLEAR,
    FAKE_ANTHROPIC_KEY,
    FAKE_AWS_KEY,
    FAKE_ENTROPY_SECRET,
    FAKE_GITHUB_TOKEN,
    FAKE_SECRETS,
    KITCHEN_SINK,
    RTL_OVERRIDE,
    ZERO_WIDTH_SPACE,
)
from mcpscan.adapters.base import ServerDecl
from mcpscan.checks.secrets import check_server_env
from mcpscan.checks.tool_integrity import check_tool_integrity
from mcpscan.domain import Report
from mcpscan.engine import scan
from mcpscan.redaction import fingerprint_secret, mask
from mcpscan.report import RenderOptions
from mcpscan.report.html import render_html
from mcpscan.report.json_report import render_json
from mcpscan.report.sarif import render_sarif
from mcpscan.report.terminal import render_terminal

#: Secret shapes that are awkward to handle correctly — each is still a secret.
AWKWARD_SECRETS: tuple[str, ...] = (
    *FAKE_SECRETS,
    FAKE_ENTROPY_SECRET,
    f"{FAKE_ANTHROPIC_KEY}{ZERO_WIDTH_SPACE}",  # hidden character inside the key
    f"{RTL_OVERRIDE}{FAKE_GITHUB_TOKEN}",  # bidi-prefixed
    f"{ANSI_CLEAR}{FAKE_AWS_KEY}",  # escape-prefixed
    FAKE_ANTHROPIC_KEY + ".*+?[](){}|^$\\",  # regex metacharacters
)


def _scan_with_secret(root: Path, secret: str, home: Path) -> Report:
    """Plant ``secret`` on every input surface under ``root`` and scan it."""
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "leaky": {
                        "command": "npx",
                        "args": ["-y", "server", f"--token={secret}"],
                        "env": {"ANTHROPIC_API_KEY": secret, "NOTE": KITCHEN_SINK},
                        "autoApprove": ["*"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (root / ".env").write_text(f"GITHUB_TOKEN={secret}\n", encoding="utf-8")
    return scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)


def _all_renderings(report: Report, *, show_secrets: bool) -> dict[str, str]:
    """Every text artifact the tool can produce from a report."""
    opts = RenderOptions(show_secrets=show_secrets)
    return {
        "terminal": render_terminal(report, opts),
        "json": render_json(report, opts),
        "html": render_html(report, opts),
        "sarif": render_sarif(report, opts, base="/repo"),
    }


@pytest.mark.parametrize("secret", AWKWARD_SECRETS, ids=lambda s: repr(s[:18]))
def test_no_renderer_emits_a_raw_secret(secret: str, tmp_path: Path) -> None:
    """The core guarantee (FR-R4, NFR-SEC2): no output holds the raw value."""
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    report = _scan_with_secret(root, secret, home)

    # The scan must actually have found it — otherwise this proves nothing.
    assert any(f.secret is not None for s in report.servers for f in s.findings), (
        "no secret detected; the leak sweep would be vacuous"
    )

    for name, text in _all_renderings(report, show_secrets=False).items():
        assert secret not in text, f"{name} renderer leaked the raw secret"


@pytest.mark.parametrize("secret", AWKWARD_SECRETS, ids=lambda s: repr(s[:18]))
def test_show_secrets_reveals_only_the_mask(secret: str, tmp_path: Path) -> None:
    """Even the explicit opt-in never reveals the whole value.

    ``--show-secrets`` is the one flag that widens exposure, so it is exactly
    where a regression would go unnoticed: it must still print at most the
    first-2/last-2 mask, never the raw string.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    report = _scan_with_secret(root, secret, home)

    for name, text in _all_renderings(report, show_secrets=True).items():
        assert secret not in text, f"{name} renderer leaked the raw secret under --show-secrets"


@pytest.mark.parametrize("secret", AWKWARD_SECRETS, ids=lambda s: repr(s[:18]))
def test_alert_payload_carries_only_the_triage_handle(secret: str, tmp_path: Path) -> None:
    """The emit payload goes to a webhook or a shared log — it must be thinnest.

    Not even the mask is allowed here: an alert leaves the machine, so a
    fingerprint's 8 hex characters are the whole budget.
    """
    from mcpscan.emit import build_emit_payload

    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    report = _scan_with_secret(root, secret, home)

    payload = build_emit_payload(
        report, kind="scan", generated_at="2026-01-01T00:00:00Z", gate_failed=True, threshold="high"
    )
    serialized = json.dumps(payload, ensure_ascii=False)
    assert secret not in serialized
    assert mask(secret) not in serialized
    for finding in payload["findings"]:  # type: ignore[union-attr]
        assert set(finding) <= {"id", "dimension", "severity", "title", "location", "sha256_8"}


@pytest.mark.parametrize("secret", AWKWARD_SECRETS, ids=lambda s: repr(s[:18]))
def test_baseline_snapshot_never_carries_a_secret(secret: str, tmp_path: Path) -> None:
    """A baseline is committed to git — the highest-consequence sink of all."""
    from mcpscan.drift.baseline import render_baseline
    from mcpscan.drift.snapshot import build_snapshot

    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    report = _scan_with_secret(root, secret, home)
    text = render_baseline(build_snapshot(report), created_at="2026-01-01")
    assert secret not in text
    assert mask(secret) not in text


def test_a_secret_in_an_env_value_never_appears_in_a_tool_integrity_finding() -> None:
    """Cross-check findings quote the *key*, never the value.

    ``TOOL-HIDDEN-UNICODE`` fires on the shape of a value, so it is one of the
    few places a check reasons about a string that may itself be a credential.
    It names the surface (``env value 'API_KEY'``) and the codepoints — never the
    value.
    """
    poisoned = f"{FAKE_ANTHROPIC_KEY}{ZERO_WIDTH_SPACE}"
    decl = ServerDecl(name="srv", command="x", env=(("ANTHROPIC_API_KEY", poisoned),))
    findings = check_tool_integrity(decl, "/repo/.mcp.json")
    assert findings, "expected the hidden-unicode finding to fire"
    for finding in findings:
        blob = f"{finding.title}{finding.rationale}{finding.remediation}{finding.location.path}"
        assert FAKE_ANTHROPIC_KEY not in blob
        assert "ANTHROPIC_API_KEY" in finding.title  # the key IS named — that is the point


def test_reuse_finding_names_paths_not_values(tmp_path: Path) -> None:
    """The blast-radius join must not repeat another finding's mask.

    ``CRED-REUSE`` is the one check that reasons across findings, so it is where
    a second server's secret material could accidentally be interpolated into
    the first server's rationale.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {"command": "x", "env": {"API_KEY": FAKE_ANTHROPIC_KEY}},
                    "b": {"command": "y", "env": {"API_KEY": FAKE_ANTHROPIC_KEY}},
                }
            }
        ),
        encoding="utf-8",
    )
    report = scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    reuse = [f for s in report.servers for f in s.findings if f.id == "CRED-REUSE"]
    assert reuse, "expected the cross-server reuse finding"
    for finding in reuse:
        assert FAKE_ANTHROPIC_KEY not in finding.rationale
        assert mask(FAKE_ANTHROPIC_KEY) not in finding.rationale


# --- the redaction primitive itself ------------------------------------------
@pytest.mark.parametrize("secret", AWKWARD_SECRETS, ids=lambda s: repr(s[:18]))
def test_fingerprint_is_not_reversible(secret: str) -> None:
    """A fingerprint reveals length, 32 bits of hash, and at most 4 characters."""
    fingerprint = fingerprint_secret(secret)
    assert secret not in fingerprint.masked
    assert secret not in fingerprint.sha256_8
    assert len(fingerprint.sha256_8) == 8
    assert fingerprint.length == len(secret)
    visible = fingerprint.masked.replace("*", "")
    assert len(visible) <= 4


@pytest.mark.parametrize("length", [0, 1, 2, 3, 4])
def test_short_secrets_are_masked_entirely(length: int) -> None:
    """The boundary an attacker would probe: a short token must not be readable.

    At or below four characters, first-2/last-2 would be the whole value, so the
    mask degrades to full redaction instead.
    """
    raw = "s3cr"[:length] or ""
    assert set(mask(raw)) <= {"*"}


def test_mask_reveals_at_most_two_characters_each_side() -> None:
    """Documented, deliberate exposure — pinned so it cannot widen silently."""
    assert mask("A" * 5) == "AA*AA"
    assert mask(FAKE_ANTHROPIC_KEY).startswith("sk")
    assert mask(FAKE_ANTHROPIC_KEY).count("*") == len(FAKE_ANTHROPIC_KEY) - 4


def test_fingerprints_collide_only_by_value() -> None:
    """Equal secrets fingerprint equally (that is what powers CRED-REUSE);
    different secrets do not."""
    assert fingerprint_secret("same-value") == fingerprint_secret("same-value")
    assert fingerprint_secret("a-value") != fingerprint_secret("b-value")


# --- process and file surfaces ------------------------------------------------
def test_process_env_secret_is_fingerprinted_at_detection() -> None:
    """The opt-in process-env surface reads live credentials — same boundary."""
    from mcpscan.checks.secrets import check_process_env_secrets
    from mcpscan.discovery.process_env import ProcessEnv

    entry = ProcessEnv(
        pid=4242,
        proc_name="claude-mcp",
        env=(("ANTHROPIC_API_KEY", FAKE_ANTHROPIC_KEY),),
        cmdline="claude-mcp --serve",
    )
    findings = check_process_env_secrets([entry])
    assert findings
    for finding in findings:
        blob = f"{finding.title}{finding.rationale}{finding.remediation}{finding.location.path}"
        assert FAKE_ANTHROPIC_KEY not in blob
        assert finding.secret is not None


def test_env_block_secret_never_reaches_the_finding_text() -> None:
    decl = ServerDecl(name="s", command="x", env=(("API_KEY", FAKE_ANTHROPIC_KEY),))
    findings = check_server_env(decl, "/repo/.mcp.json")
    assert findings
    for finding in findings:
        assert FAKE_ANTHROPIC_KEY not in f"{finding.title}{finding.rationale}"


@posix_only
def test_written_reports_are_owner_only(tmp_path: Path) -> None:
    """FR-R6: a report names findings, so it must not be world-readable.

    The permission is set at ``open()`` time, so there is no window in which the
    file exists with default permissions — and it is re-applied afterwards in
    case the path already existed with looser bits.
    """
    from mcpscan.report.writer import write_report

    target = tmp_path / "report.json"
    target.write_text("pre-existing", encoding="utf-8")
    target.chmod(0o666)
    write_report(target, "content")
    assert target.stat().st_mode & 0o777 == 0o600
