# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Acceptance ledger: parsing, expiry, scope guardrail, application (Feature D)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import date
from pathlib import Path

from mcpscan.acceptance import (
    LEDGER_FILENAME,
    LedgerEntry,
    acceptance_expired,
    apply_acceptances,
    load_ledgers,
    parse_ledger,
)
from mcpscan.domain import Dimension, Finding, Report, Server, ServerState, Severity
from mcpscan.scoring import grade_findings

TODAY = date(2026, 8, 11)


def _entry(**overrides: str) -> LedgerEntry:
    base = {
        "finding": "SCOPE-DANGEROUS-ALLOW",
        "server": "permissions",
        "owner": "Jane Doe",
        "accepted": "2026-08-11",
        "expires": "2026-11-11",
        "reason": "CI runner is ephemeral",
    }
    base.update(overrides)
    return LedgerEntry(**base)


def _ledger_json(*entries: dict[str, object]) -> str:
    return json.dumps({"acceptances": list(entries)})


def _entry_dict(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "finding": "SCOPE-DANGEROUS-ALLOW",
        "server": "permissions",
        "owner": "Jane Doe",
        "accepted": "2026-08-11",
        "expires": "2026-11-11",
        "reason": "CI runner is ephemeral",
    }
    base.update(overrides)
    return base


def _scoped_report(*findings: Finding, server_id: str = "/cfg/.mcp.json#permissions") -> Report:
    server = Server(
        id=server_id,
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=findings,
    )
    return Report(
        schema_version="1.1",
        servers=(server,),
        overall_grade=grade_findings(findings),
        dimension_grades={},
    )


# --- parse_ledger ---
def test_parse_ledger_valid_entry() -> None:
    loaded = parse_ledger(_ledger_json(_entry_dict()), "ledger.json")
    assert loaded.warnings == ()
    assert loaded.entries == (_entry(),)


def test_parse_ledger_optional_fields_default_empty() -> None:
    raw = _entry_dict()
    del raw["accepted"]
    del raw["reason"]
    loaded = parse_ledger(_ledger_json(raw), "ledger.json")
    assert loaded.entries[0].accepted == ""
    assert loaded.entries[0].reason == ""


def test_parse_ledger_bad_json_warns_and_yields_nothing() -> None:
    loaded = parse_ledger("{not json", "ledger.json")
    assert loaded.entries == ()
    assert len(loaded.warnings) == 1
    assert "malformed acceptance ledger ledger.json" in loaded.warnings[0]


def test_parse_ledger_wrong_top_level_shape_warns() -> None:
    for text in ("[]", '{"acceptances": {}}', '"just a string"'):
        loaded = parse_ledger(text, "ledger.json")
        assert loaded.entries == ()
        assert any("malformed" in w for w in loaded.warnings)


def test_parse_ledger_entry_missing_owner_is_skipped_with_warning() -> None:
    raw = _entry_dict(owner="   ")  # whitespace-only: no named human owner
    loaded = parse_ledger(_ledger_json(raw), "ledger.json")
    assert loaded.entries == ()
    assert any("owner" in w for w in loaded.warnings)


def test_parse_ledger_entry_bad_expires_date_is_skipped() -> None:
    loaded = parse_ledger(_ledger_json(_entry_dict(expires="soonish")), "ledger.json")
    assert loaded.entries == ()
    assert any("expires" in w for w in loaded.warnings)


def test_parse_ledger_non_dict_entry_is_skipped_others_survive() -> None:
    loaded = parse_ledger(json.dumps({"acceptances": ["nope", _entry_dict()]}), "ledger.json")
    assert len(loaded.entries) == 1
    assert any("#1" in w for w in loaded.warnings)


# --- acceptance_expired ---
def test_acceptance_holds_through_its_expiry_date() -> None:
    # "accepted until" is inclusive: the expiry date itself still holds.
    assert acceptance_expired("2026-08-11", today=TODAY) is False
    assert acceptance_expired("2026-08-10", today=TODAY) is True
    assert acceptance_expired("2026-08-12", today=TODAY) is False


# --- apply_acceptances ---
def test_apply_attaches_acceptance_via_server_suffix(
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(
        id="SCOPE-DANGEROUS-ALLOW", dimension=Dimension.TOOL_SCOPE, severity=Severity.HIGH
    )
    report = _scoped_report(finding)  # id ends with "#permissions"
    applied, warnings = apply_acceptances(report, [_entry()], today=TODAY)
    assert warnings == ()
    acceptance = applied.servers[0].findings[0].acceptance
    assert acceptance is not None
    assert acceptance.owner == "Jane Doe"
    assert acceptance.expires == "2026-11-11"
    assert acceptance.expired is False


def test_apply_matches_exact_server_id(make_finding: Callable[..., Finding]) -> None:
    finding = make_finding(
        id="SCOPE-DANGEROUS-ALLOW", dimension=Dimension.TOOL_SCOPE, severity=Severity.HIGH
    )
    report = _scoped_report(finding)
    entry = _entry(server="/cfg/.mcp.json#permissions")
    applied, _ = apply_acceptances(report, [entry], today=TODAY)
    assert applied.servers[0].findings[0].acceptance is not None


def test_apply_refuses_non_tool_scope_with_warning(
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(id="CRED-PLAINTEXT", dimension=Dimension.CREDENTIAL)
    report = _scoped_report(finding, server_id="/cfg/.mcp.json#leaky")
    entry = _entry(finding="CRED-PLAINTEXT", server="leaky")
    applied, warnings = apply_acceptances(report, [entry], today=TODAY)
    assert applied.servers[0].findings[0].acceptance is None  # guardrail held
    assert len(warnings) == 1
    assert "cannot be risk-accepted" in warnings[0]


def test_apply_expired_acceptance_is_attached_but_flagged(
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(
        id="SCOPE-DANGEROUS-ALLOW", dimension=Dimension.TOOL_SCOPE, severity=Severity.HIGH
    )
    report = _scoped_report(finding)
    applied, warnings = apply_acceptances(report, [_entry(expires="2026-05-01")], today=TODAY)
    assert warnings == ()
    acceptance = applied.servers[0].findings[0].acceptance
    assert acceptance is not None and acceptance.expired is True


def test_apply_prefers_unexpired_renewal_over_lapsed_entry(
    make_finding: Callable[..., Finding],
) -> None:
    # An operator appends a renewal after a lapse; the stale entry above it
    # must not shadow the valid one (reviewer finding, acceptance.py).
    finding = make_finding(
        id="SCOPE-DANGEROUS-ALLOW", dimension=Dimension.TOOL_SCOPE, severity=Severity.HIGH
    )
    report = _scoped_report(finding)
    lapsed = _entry(expires="2026-04-01")
    renewal = _entry(expires="2026-11-11")
    applied, warnings = apply_acceptances(report, [lapsed, renewal], today=TODAY)
    assert warnings == ()
    acceptance = applied.servers[0].findings[0].acceptance
    assert acceptance is not None
    assert acceptance.expired is False
    assert acceptance.expires == "2026-11-11"


def test_apply_falls_back_to_expired_entry_when_no_valid_renewal(
    make_finding: Callable[..., Finding],
) -> None:
    # With only lapsed entries, the first one is still attached (flagged) so
    # the renderers can be loud about who let it lapse and when.
    finding = make_finding(
        id="SCOPE-DANGEROUS-ALLOW", dimension=Dimension.TOOL_SCOPE, severity=Severity.HIGH
    )
    report = _scoped_report(finding)
    first, second = _entry(expires="2026-03-01"), _entry(expires="2026-05-01")
    applied, _ = apply_acceptances(report, [first, second], today=TODAY)
    acceptance = applied.servers[0].findings[0].acceptance
    assert acceptance is not None
    assert acceptance.expired is True
    assert acceptance.expires == "2026-03-01"


def test_apply_without_match_changes_nothing(make_finding: Callable[..., Finding]) -> None:
    finding = make_finding(
        id="SCOPE-WILDCARD", dimension=Dimension.TOOL_SCOPE, severity=Severity.MEDIUM
    )
    report = _scoped_report(finding, server_id="/cfg/.mcp.json#other")
    applied, warnings = apply_acceptances(report, [_entry()], today=TODAY)
    assert applied == report  # different server suffix and finding id: untouched
    assert warnings == ()


def test_apply_leaves_grades_untouched(make_finding: Callable[..., Finding]) -> None:
    # The gate-vs-grade stance: acceptance never changes what scoring sees.
    finding = make_finding(
        id="SCOPE-DANGEROUS-ALLOW", dimension=Dimension.TOOL_SCOPE, severity=Severity.HIGH
    )
    report = _scoped_report(finding)
    applied, _ = apply_acceptances(report, [_entry()], today=TODAY)
    assert applied.overall_grade == report.overall_grade
    assert grade_findings(applied.servers[0].findings) == grade_findings(report.servers[0].findings)


def test_apply_with_no_entries_is_identity(make_finding: Callable[..., Finding]) -> None:
    report = _scoped_report(make_finding(id="X", dimension=Dimension.TOOL_SCOPE))
    applied, warnings = apply_acceptances(report, [], today=TODAY)
    assert applied is report
    assert warnings == ()


# --- load_ledgers (the I/O edge) ---
def test_load_ledgers_missing_file_is_silent(tmp_path: Path) -> None:
    loaded = load_ledgers([tmp_path])
    assert loaded.entries == () and loaded.warnings == ()


def test_load_ledgers_reads_entries_and_warns_on_bad_rows(tmp_path: Path) -> None:
    (tmp_path / LEDGER_FILENAME).write_text(
        json.dumps({"acceptances": [_entry_dict(), _entry_dict(owner="")]}), encoding="utf-8"
    )
    loaded = load_ledgers([tmp_path])
    assert len(loaded.entries) == 1
    assert len(loaded.warnings) == 1


def test_load_ledgers_concatenates_roots_in_order(tmp_path: Path) -> None:
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    for root, server in ((root_a, "one"), (root_b, "two")):
        root.mkdir()
        (root / LEDGER_FILENAME).write_text(
            json.dumps({"acceptances": [_entry_dict(server=server)]}), encoding="utf-8"
        )
    loaded = load_ledgers([root_a, root_b])
    assert [e.server for e in loaded.entries] == ["one", "two"]


def test_load_ledgers_oversized_file_warns_never_crashes(tmp_path: Path) -> None:
    (tmp_path / LEDGER_FILENAME).write_text("x" * (1024 * 1024 + 1), encoding="utf-8")
    loaded = load_ledgers([tmp_path])
    assert loaded.entries == ()
    assert any("unreadable acceptance ledger" in w for w in loaded.warnings)
