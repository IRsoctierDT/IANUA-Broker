# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Agent-host telemetry/logging-health check (Wave 3 Feature L).

The check is pure over its inputs; "now" and the log mtime are always injected
integers, and only log *metadata* (presence/mode/mtime) is ever passed in.
"""

from __future__ import annotations

from mcpscan.adapters.claude import ClaudeAdapter
from mcpscan.adapters.cursor import CursorAdapter
from mcpscan.checks.telemetry import check_telemetry
from mcpscan.domain import Dimension, Severity

# One realistic "now" and mtimes on either side of a 30-day staleness window.
_NOW = 2_000_000_000
_DAY = 24 * 60 * 60
_FRESH = _NOW - 3 * _DAY  # 3 days old -> not stale
_OLD = _NOW - 90 * _DAY  # 90 days old -> stale


# --- absent / empty surface ---
def test_absent_surface_flags_absent_low() -> None:
    findings = check_telemetry(
        "/logs/Claude", present=False, mode=None, mtime_epoch=None, now_epoch=_NOW
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "TELEMETRY-ABSENT"
    assert f.dimension is Dimension.EXPOSURE
    assert f.severity is Severity.LOW
    assert f.location.path == "/logs/Claude"


def test_absent_takes_precedence_over_perms_and_stale() -> None:
    # When nothing is present, mode/mtime are moot: only ABSENT fires.
    findings = check_telemetry("/logs", present=False, mode=0o644, mtime_epoch=_OLD, now_epoch=_NOW)
    assert [f.id for f in findings] == ["TELEMETRY-ABSENT"]


# --- permissions ---
def test_world_readable_log_flags_perms_medium() -> None:
    findings = check_telemetry(
        "/logs/a.log", present=True, mode=0o644, mtime_epoch=_FRESH, now_epoch=_NOW
    )
    assert [f.id for f in findings] == ["TELEMETRY-PERMS"]
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].dimension is Dimension.EXPOSURE
    assert "chmod 600" in findings[0].remediation


def test_group_readable_log_flags_perms() -> None:
    # group-read only (0o040) still trips the 0o077 mask.
    findings = check_telemetry("/l", present=True, mode=0o640, mtime_epoch=_FRESH, now_epoch=_NOW)
    assert any(f.id == "TELEMETRY-PERMS" for f in findings)


def test_owner_only_fresh_log_yields_no_finding() -> None:
    # Present, 0o600, and recently written: healthy -> silent.
    assert check_telemetry("/l", present=True, mode=0o600, mtime_epoch=_FRESH, now_epoch=_NOW) == []


def test_unknown_mode_yields_no_perms_finding() -> None:
    # Off POSIX the mode is None; the perms rule must not fire (POSIX lesson).
    assert check_telemetry("/l", present=True, mode=None, mtime_epoch=_FRESH, now_epoch=_NOW) == []


# --- staleness ---
def test_stale_log_flags_stale_info() -> None:
    findings = check_telemetry("/l", present=True, mode=0o600, mtime_epoch=_OLD, now_epoch=_NOW)
    assert [f.id for f in findings] == ["TELEMETRY-STALE"]
    assert findings[0].severity is Severity.INFO


def test_fresh_log_is_not_stale() -> None:
    assert check_telemetry("/l", present=True, mode=0o600, mtime_epoch=_FRESH, now_epoch=_NOW) == []


def test_staleness_boundary_is_strict() -> None:
    # Exactly at the window is NOT stale; only strictly older is.
    at_edge = _NOW - 30 * _DAY
    assert (
        check_telemetry("/l", present=True, mode=0o600, mtime_epoch=at_edge, now_epoch=_NOW) == []
    )
    just_over = at_edge - 1
    ids = {
        f.id
        for f in check_telemetry(
            "/l", present=True, mode=0o600, mtime_epoch=just_over, now_epoch=_NOW
        )
    }
    assert ids == {"TELEMETRY-STALE"}


def test_staleness_skipped_without_now_epoch() -> None:
    # No injected clock -> no staleness grade (determinism guardrail).
    assert check_telemetry("/l", present=True, mode=0o600, mtime_epoch=_OLD, now_epoch=None) == []


def test_staleness_skipped_without_mtime() -> None:
    assert check_telemetry("/l", present=True, mode=0o600, mtime_epoch=None, now_epoch=_NOW) == []


def test_custom_staleness_window() -> None:
    # The threshold is injectable; a 1-day window flags a 3-day-old log.
    findings = check_telemetry(
        "/l", present=True, mode=0o600, mtime_epoch=_FRESH, now_epoch=_NOW, stale_after_seconds=_DAY
    )
    assert [f.id for f in findings] == ["TELEMETRY-STALE"]


def test_perms_and_stale_can_both_fire() -> None:
    ids = {
        f.id
        for f in check_telemetry("/l", present=True, mode=0o644, mtime_epoch=_OLD, now_epoch=_NOW)
    }
    assert ids == {"TELEMETRY-PERMS", "TELEMETRY-STALE"}


# --- adapter telemetry registry ---
def test_claude_adapter_registers_log_dir_on_macos() -> None:
    paths = ClaudeAdapter().telemetry_surfaces("Darwin", {"HOME": "/Users/u"})
    assert [str(p) for p in paths] == ["/Users/u/Library/Logs/Claude"]


def test_claude_adapter_registers_log_dir_on_windows() -> None:
    paths = ClaudeAdapter().telemetry_surfaces(
        "Windows", {"APPDATA": r"C:\Users\u\AppData\Roaming"}
    )
    assert [str(p) for p in paths] == [r"C:\Users\u\AppData\Roaming\Claude\logs"]


def test_claude_adapter_registers_nothing_on_linux() -> None:
    # No documented Claude Desktop Linux log path -> conservative empty.
    assert ClaudeAdapter().telemetry_surfaces("Linux", {"HOME": "/home/u"}) == []


def test_claude_adapter_needs_home_on_macos() -> None:
    assert ClaudeAdapter().telemetry_surfaces("Darwin", {}) == []


def test_other_adapter_registers_no_telemetry_surface() -> None:
    # The default seam returns nothing rather than guessing a location.
    assert CursorAdapter().telemetry_surfaces("Darwin", {"HOME": "/Users/u"}) == []
