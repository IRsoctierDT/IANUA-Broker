# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Tier-4 agent trust: factor scoring, risk relationships, grading, rendering."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.adapters.base import ParsedConfig, ServerDecl
from mcpscan.report import RenderOptions
from mcpscan.trust import (
    TrustFactor,
    TrustProfile,
    analyze_config,
    apply_shared_credentials,
    build_trust_report,
    collect_trust,
    config_credential_fingerprints,
    profile_server,
)
from mcpscan.trust.render import render_json_trust, render_terminal_trust

_SECRET = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_SECRET2 = "sk-ant-api03-ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"


def _factor(profile: object, factor: TrustFactor) -> int:
    from mcpscan.trust.model import TrustProfile

    assert isinstance(profile, TrustProfile)
    return next(f.risk for f in profile.factors if f.factor is factor)


def _rel_ids(profile: object) -> set[str]:
    from mcpscan.trust.model import TrustProfile

    assert isinstance(profile, TrustProfile)
    return {r.id for r in profile.relationships}


# --- individual factors ---
def test_clean_server_is_fully_trusted() -> None:
    server = ServerDecl(name="safe", command="npx", args=("db-mcp-server@1.2.3",))
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert profile.score == 100 and profile.grade == "A"
    assert profile.relationships == ()
    assert profile.present_factors == ()


def test_secret_access_lowers_trust() -> None:
    server = ServerDecl(
        name="db", command="npx", args=("pg@1.0.0",), env=(("PGPASSWORD", _SECRET),)
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.SECRET_ACCESS) == 25
    assert profile.score == 75


def test_multiple_secrets_add_risk_up_to_cap() -> None:
    env = tuple((f"KEY{i}", _SECRET) for i in range(6))
    server = ServerDecl(name="db", command="npx", args=("pg@1.0.0",), env=env)
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.SECRET_ACCESS) == 40  # capped


def test_dangerous_autoapprove_is_privilege_and_autonomy() -> None:
    server = ServerDecl(name="sh", command="npx", args=("x@1.0.0",), auto_approve=("run_command",))
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.TOOL_PRIVILEGE) == 25
    assert _factor(profile, TrustFactor.AUTONOMY) == 15


def test_wildcard_grant_adds_privilege() -> None:
    server = ServerDecl(name="w", command="npx", args=("x@1.0.0",), auto_approve=("mcp__*",))
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.TOOL_PRIVILEGE) == 20


def test_unpinned_runner_flags_provenance() -> None:
    server = ServerDecl(name="u", command="npx", args=("some-server",))  # no @version
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.CODE_PROVENANCE) == 10


# --- risk relationships: the differentiator ---
def test_privileged_secret_holder_relationship() -> None:
    server = ServerDecl(
        name="db",
        command="npx",
        args=("pg@1.0.0",),
        env=(("PGPASSWORD", _SECRET),),
        auto_approve=("run_command",),
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    ids = _rel_ids(profile)
    assert "PRIVILEGED-SECRET-HOLDER" in ids
    assert "AUTONOMOUS-PRIVILEGED" in ids
    assert "AUTONOMOUS-SECRET-HOLDER" in ids


def test_unvetted_privileged_relationship() -> None:
    server = ServerDecl(
        name="u", command="npx", args=("some-server",), auto_approve=("run_command",)
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert "UNVETTED-PRIVILEGED" in _rel_ids(profile)


# --- AUTONOMOUS-EXFIL-PATH triple composite (Wave 2 Feature I) ---
def _exfil_server() -> ServerDecl:
    # one dangerous auto-approved tool gives TOOL_PRIVILEGE + AUTONOMY, the env
    # secret gives SECRET_ACCESS — all three factors on a single subject.
    return ServerDecl(
        name="agent",
        command="npx",
        args=("pg@1.0.0",),  # pinned: no provenance risk
        env=(("PGPASSWORD", _SECRET),),
        auto_approve=("run_command",),
    )


def test_autonomous_exfil_path_present_when_all_three_factors() -> None:
    profile = profile_server(_exfil_server(), "/cfg/.mcp.json", "claude")
    ids = _rel_ids(profile)
    assert "AUTONOMOUS-EXFIL-PATH" in ids
    # the pair relationships it subsumes still fire alongside it
    assert {"PRIVILEGED-SECRET-HOLDER", "AUTONOMOUS-PRIVILEGED", "AUTONOMOUS-SECRET-HOLDER"} <= ids
    exfil = next(r for r in profile.relationships if r.id == "AUTONOMOUS-EXFIL-PATH")
    assert exfil.title == "Autonomous exfiltration path"
    assert exfil.factors == (
        TrustFactor.AUTONOMY,
        TrustFactor.TOOL_PRIVILEGE,
        TrustFactor.SECRET_ACCESS,
    )


def test_autonomous_exfil_path_reads_as_the_headline() -> None:
    # emitted first so the triple leads over the pair relationships
    profile = profile_server(_exfil_server(), "/cfg/.mcp.json", "claude")
    assert profile.relationships[0].id == "AUTONOMOUS-EXFIL-PATH"


def test_autonomous_exfil_path_does_not_change_score() -> None:
    # relationship only: score is exactly the factor sum, so the composite adds
    # zero points (the three factors are already billed individually).
    profile = profile_server(_exfil_server(), "/cfg/.mcp.json", "claude")
    total_risk = sum(f.risk for f in profile.factors)
    assert profile.score == 100 - total_risk == 35  # 25 secret + 25 danger + 15 autonomy
    assert profile.grade == "F"


def test_autonomous_exfil_path_needs_all_three_factors() -> None:
    # secret + autonomy but a NON-dangerous, non-wildcard tool → no TOOL_PRIVILEGE
    server = ServerDecl(
        name="agent",
        command="npx",
        args=("pg@1.0.0",),
        env=(("PGPASSWORD", _SECRET),),
        auto_approve=("read_file",),
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    ids = _rel_ids(profile)
    assert "AUTONOMOUS-EXFIL-PATH" not in ids
    assert "AUTONOMOUS-SECRET-HOLDER" in ids  # the two-factor pair still fires


def test_autonomous_exfil_path_renders_in_terminal_and_json() -> None:
    report = build_trust_report([profile_server(_exfil_server(), "/cfg/.mcp.json", "claude")])
    terminal = render_terminal_trust(report, RenderOptions())
    assert "AUTONOMOUS-EXFIL-PATH" in terminal
    assert "Autonomous exfiltration path" in terminal
    assert _SECRET not in terminal
    out = render_json_trust(report, RenderOptions())
    payload = json.loads(out)
    rels = payload["profiles"][0]["relationships"]
    exfil = next(r for r in rels if r["id"] == "AUTONOMOUS-EXFIL-PATH")
    assert exfil["factors"] == ["autonomy", "tool_privilege", "secret_access"]
    assert _SECRET not in out
    assert payload["schema_version"] == "1.0"  # data change only — no shape bump


def test_secrets_alone_create_no_relationship() -> None:
    server = ServerDecl(
        name="db", command="npx", args=("pg@1.0.0",), env=(("PGPASSWORD", _SECRET),)
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert profile.relationships == ()  # one factor is not a combination


def test_score_floors_at_zero() -> None:
    env = tuple((f"KEY{i}", _SECRET) for i in range(6))  # 40
    server = ServerDecl(
        name="worst",
        command="npx",
        args=("some-server",),  # unpinned: 10
        env=env,
        auto_approve=("run_command", "mcp__*"),  # 40 + autonomy 15
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert profile.score == 0 and profile.grade == "F"


# --- report assembly ---
def test_report_grades_by_worst_subject() -> None:
    clean = ServerDecl(name="safe", command="npx", args=("x@1.0.0",))
    risky = ServerDecl(name="db", command="npx", args=("pg@1.0.0",), env=(("PGPASSWORD", _SECRET),))
    config = ParsedConfig(path="/cfg/.mcp.json", servers=(clean, risky))
    report = build_trust_report(analyze_config(config, "claude"))
    assert report.overall_grade == "C"  # 75 -> C is the worst
    assert report.profiles[0].server_name == "db"  # worst score sorts first
    assert len(report.risky) == 0  # secrets alone -> no relationship


# --- rendering ---
def test_terminal_render_lists_relationships() -> None:
    server = ServerDecl(
        name="db",
        command="npx",
        args=("pg@1.0.0",),
        env=(("PGPASSWORD", _SECRET),),
        auto_approve=("run_command",),
    )
    report = build_trust_report([profile_server(server, "/cfg/.mcp.json", "claude")])
    out = render_terminal_trust(report, RenderOptions())
    assert "Trust" in out and "PRIVILEGED-SECRET-HOLDER" in out
    assert _SECRET not in out  # never leaks the raw secret


def test_terminal_render_empty() -> None:
    report = build_trust_report([])
    out = render_terminal_trust(report, RenderOptions())
    assert "No MCP servers found" in out


def test_json_render_is_stable_and_secretless() -> None:
    server = ServerDecl(
        name="db", command="npx", args=("pg@1.0.0",), env=(("PGPASSWORD", _SECRET),)
    )
    report = build_trust_report([profile_server(server, "/cfg/.mcp.json", "claude")])
    first = render_json_trust(report, RenderOptions())
    assert first == render_json_trust(report, RenderOptions())
    payload = json.loads(first)
    assert payload["schema_version"] == "1.0"
    assert payload["profiles"][0]["score"] == 75
    assert _SECRET not in first


# --- SHARED-CREDENTIAL blast radius (Wave 1 Feature C) ---
def _shared_secret_profiles(secret_a: str, secret_b: str) -> list[TrustProfile]:
    a = ServerDecl(name="a", command="npx", args=("x@1.0.0",), env=(("API_KEY", secret_a),))
    b = ServerDecl(name="b", command="npx", args=("y@1.0.0",), env=(("TOKEN", secret_b),))
    config = ParsedConfig(path="/cfg/.mcp.json", servers=(a, b))
    return apply_shared_credentials(
        analyze_config(config, "claude"), config_credential_fingerprints(config)
    )


def test_shared_credential_relationship_without_score_change() -> None:
    profiles = _shared_secret_profiles(_SECRET, _SECRET)
    assert len(profiles) == 2
    for profile in profiles:
        rel = next(r for r in profile.relationships if r.id == "SHARED-CREDENTIAL")
        assert rel.factors == (TrustFactor.SECRET_ACCESS,)
        assert "1 other tool(s)" in rel.rationale
        assert profile.score == 75  # relationship only — SECRET_ACCESS already billed


def test_distinct_secrets_share_no_credential() -> None:
    profiles = _shared_secret_profiles(_SECRET, _SECRET2)
    for profile in profiles:
        assert "SHARED-CREDENTIAL" not in _rel_ids(profile)


def test_same_secret_twice_on_one_subject_is_not_shared() -> None:
    solo = ServerDecl(
        name="a",
        command="npx",
        args=("x@1.0.0",),
        env=(("API_KEY", _SECRET), ("EXTRA_TOKEN", _SECRET)),
    )
    config = ParsedConfig(path="/cfg/.mcp.json", servers=(solo,))
    profiles = apply_shared_credentials(
        analyze_config(config, "claude"), config_credential_fingerprints(config)
    )
    assert profiles[0].relationships == ()  # needs >= 2 distinct subjects


def test_collect_trust_shared_credential_across_configs(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {"command": "npx", "args": ["x@1.0.0"], "env": {"API_KEY": _SECRET}}
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "b": {"command": "npx", "args": ["y@1.0.0"], "env": {"TOKEN": _SECRET}}
                }
            }
        ),
        encoding="utf-8",
    )
    report = collect_trust(roots=[tmp_path], system="Linux", env={})
    shared = [p for p in report.profiles if "SHARED-CREDENTIAL" in {r.id for r in p.relationships}]
    assert {p.server_name for p in shared} == {"a", "b"}
    assert all(p.score == 75 for p in shared)  # no double-billing
    assert report.risky  # the relationship marks both as risky subjects
    out = render_json_trust(report, RenderOptions())
    assert _SECRET not in out  # a raw secret never reaches trust output
    assert json.loads(out)["schema_version"] == "1.0"  # data change only — no shape bump


# --- collection end to end ---
def test_collect_trust_from_real_config(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "db": {
                        "command": "npx",
                        "args": ["pg-mcp"],
                        "env": {"PGPASSWORD": _SECRET},
                        "autoApprove": ["run_command"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    report = collect_trust(roots=[tmp_path], system="Linux", env={})
    assert len(report.profiles) == 1
    profile = report.profiles[0]
    assert profile.server_name == "db"
    assert "PRIVILEGED-SECRET-HOLDER" in {r.id for r in profile.relationships}
    assert report.risky  # this tool is a risky relationship subject


def test_collect_skips_unreadable_config(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from mcpscan.io_safe import SafeReadError

    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")

    def boom(path: object, root: object) -> str:
        raise SafeReadError("unreadable")

    monkeypatch.setattr("mcpscan.trust.collect.safe_read_text", boom)
    report = collect_trust(roots=[tmp_path], system="Linux", env={})
    assert report.profiles == ()  # skipped gracefully, no crash
