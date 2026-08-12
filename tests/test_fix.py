# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the opt-in --fix remediation."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from mcpscan.fix import BACKUP_SUFFIX, apply_fix_to_file, plan_config_fixes

VULN = {
    "mcpServers": {
        "weather": {
            "command": "npx",
            "args": ["-y", "some-mcp-server@1.2.3"],
            "autoApprove": ["get_forecast", "run_command", "mcp__*"],
        },
        "safe": {"command": "npx", "args": ["-y", "x@1.0.0"], "autoApprove": ["read_only"]},
    },
    "permissions": {"allow": ["Read", "Glob(src/**)", "Bash(*)", "mcp__*"]},
}

CLEAN = {
    "mcpServers": {"safe": {"command": "npx", "args": ["-y", "x@1.0.0"]}},
    "permissions": {"allow": ["Read", "Glob(src/**)"]},
}


# --- planning (pure) ---
def test_removes_dangerous_and_wildcard_allow_entries() -> None:
    plan = plan_config_fixes("/cfg.json", json.dumps(VULN))
    assert plan.changed
    data = json.loads(plan.new_text or "")
    # Dangerous Bash(*) and broad mcp__* removed; scoped/safe entries kept.
    assert data["permissions"]["allow"] == ["Read", "Glob(src/**)"]
    allow_fixes = {f.removed: f.rule_id for f in plan.fixes if f.where == "permissions.allow"}
    assert allow_fixes == {"Bash(*)": "SCOPE-DANGEROUS-ALLOW", "mcp__*": "SCOPE-WILDCARD"}


def test_removes_dangerous_and_wildcard_autoapprove() -> None:
    plan = plan_config_fixes("/cfg.json", json.dumps(VULN))
    data = json.loads(plan.new_text or "")
    # run_command (dangerous) and mcp__* (wildcard) gone; get_forecast kept.
    assert data["mcpServers"]["weather"]["autoApprove"] == ["get_forecast"]
    # The already-safe server is untouched.
    assert data["mcpServers"]["safe"]["autoApprove"] == ["read_only"]
    auto_fixes = {
        f.removed: f.rule_id for f in plan.fixes if f.where == "mcpServers.weather.autoApprove"
    }
    assert auto_fixes == {
        "run_command": "SCOPE-DANGEROUS-AUTOAPPROVE",
        "mcp__*": "SCOPE-AUTOAPPROVE-WILDCARD",
    }


def test_preserves_unrelated_content() -> None:
    plan = plan_config_fixes("/cfg.json", json.dumps(VULN))
    data = json.loads(plan.new_text or "")
    # Server command/args and structure are untouched.
    assert data["mcpServers"]["weather"]["command"] == "npx"
    assert data["mcpServers"]["weather"]["args"] == ["-y", "some-mcp-server@1.2.3"]


def test_clean_config_yields_no_change() -> None:
    plan = plan_config_fixes("/cfg.json", json.dumps(CLEAN))
    assert not plan.changed
    assert plan.new_text is None
    assert plan.fixes == ()
    assert plan.error is None


def test_bad_json_is_reported_not_raised() -> None:
    plan = plan_config_fixes("/cfg.json", "{not json")
    assert plan.error is not None
    assert not plan.changed
    assert plan.new_text is None


def test_non_object_root_is_reported() -> None:
    plan = plan_config_fixes("/cfg.json", "42")
    assert plan.error == "config root is not an object"
    assert not plan.changed


def test_non_string_allow_entries_are_left_untouched() -> None:
    # A shape we don't understand (a dict inside allow) must be preserved, not dropped.
    cfg = {"permissions": {"allow": ["Bash(*)", {"weird": True}]}}
    plan = plan_config_fixes("/cfg.json", json.dumps(cfg))
    data = json.loads(plan.new_text or "")
    assert data["permissions"]["allow"] == [{"weird": True}]  # Bash(*) removed, dict kept


def test_odd_shapes_are_skipped_not_crashed() -> None:
    # A non-dict server, a missing permissions block, and a non-list allow must
    # all be tolerated: the fixer touches only the shapes it understands.
    cfg = {
        "mcpServers": {
            "weird": "not-an-object",
            "ok": {"command": "npx", "autoApprove": ["Bash(*)"]},
        }
    }
    plan = plan_config_fixes("/cfg.json", json.dumps(cfg))
    data = json.loads(plan.new_text or "")
    assert data["mcpServers"]["weird"] == "not-an-object"  # untouched
    assert data["mcpServers"]["ok"]["autoApprove"] == []  # Bash(*) removed


def test_permissions_allow_not_a_list_is_ignored() -> None:
    cfg = {"permissions": {"allow": "Bash(*)"}, "mcpServers": {}}
    plan = plan_config_fixes("/cfg.json", json.dumps(cfg))
    assert not plan.changed  # allow isn't a list -> nothing to prune, no crash


def test_planning_is_deterministic() -> None:
    a = plan_config_fixes("/cfg.json", json.dumps(VULN))
    b = plan_config_fixes("/cfg.json", json.dumps(VULN))
    assert a.new_text == b.new_text


def test_fixed_config_rescans_clean_for_tool_scope() -> None:
    # The whole point: after --fix, the tool-scope check finds nothing.
    from mcpscan.adapters.base import parse_mcp_servers
    from mcpscan.checks.tool_scope import check_permissions, check_server_auto_approve

    plan = plan_config_fixes("/cfg.json", json.dumps(VULN))
    data = json.loads(plan.new_text or "")
    allow = tuple(data["permissions"]["allow"])
    assert check_permissions(allow, "/cfg.json") == []
    for server in parse_mcp_servers(data):
        assert check_server_auto_approve(server, "/cfg.json") == []


# --- applying (I/O) ---
def test_apply_writes_backup_and_new_content(tmp_path: Path) -> None:
    cfg = tmp_path / "settings.json"
    cfg.write_text(json.dumps(VULN), encoding="utf-8")
    plan = plan_config_fixes(str(cfg), cfg.read_text(encoding="utf-8"))
    backup = apply_fix_to_file(cfg, plan.new_text or "")

    assert backup == Path(str(cfg) + BACKUP_SUFFIX)
    assert json.loads(backup.read_text(encoding="utf-8")) == VULN  # original preserved
    assert json.loads(cfg.read_text(encoding="utf-8"))["permissions"]["allow"] == [
        "Read",
        "Glob(src/**)",
    ]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_apply_preserves_file_mode(tmp_path: Path) -> None:
    cfg = tmp_path / "settings.json"
    cfg.write_text(json.dumps(VULN), encoding="utf-8")
    os.chmod(cfg, 0o600)
    plan = plan_config_fixes(str(cfg), cfg.read_text(encoding="utf-8"))
    apply_fix_to_file(cfg, plan.new_text or "")
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600
