# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""ATB-posture check: manifest parsing, predicates, and the pure grader.

Assessment-only and pure over its inputs (docs/proposals/ATB_POSTURE_CHECK.md).
Every finding rides ``Dimension.TOOL_SCOPE``; the fully-brokered, sound case
grades clean (no finding). Hostile input degrades to a finding, never a crash.
"""

from __future__ import annotations

import json

from mcpscan.adapters.base import ServerDecl
from mcpscan.checks.broker import (
    BrokerManifest,
    BrokerParseError,
    check_broker_posture,
    is_privileged,
    parse_broker_manifest,
    routes_through_broker,
)
from mcpscan.domain import Dimension, Severity


def _decl(
    name: str,
    *,
    command: str | None = None,
    args: tuple[str, ...] = (),
    auto_approve: tuple[str, ...] = (),
) -> ServerDecl:
    return ServerDecl(name=name, command=command, args=args, auto_approve=auto_approve)


def _sound(fronts: tuple[str, ...]) -> BrokerManifest:
    return BrokerManifest(
        schema_version="1.0",
        fronts=fronts,
        allowlist="least_privilege",
        tool_manifests="signed",
        audit_log="enabled",
    )


# --- parse_broker_manifest --------------------------------------------------
def test_parse_valid_manifest() -> None:
    raw = json.dumps(
        {
            "schema_version": "1.0",
            "fronts": ["~/.mcp.json#shell", "~/.mcp.json#db"],
            "allowlist": "least_privilege",
            "tool_manifests": "signed",
            "audit_log": "enabled",
        }
    )
    manifest = parse_broker_manifest(raw)
    assert isinstance(manifest, BrokerManifest)
    assert manifest.fronts == ("~/.mcp.json#shell", "~/.mcp.json#db")
    assert manifest.allowlist == "least_privilege"
    assert manifest.tool_manifests == "signed"
    assert manifest.audit_log == "enabled"


def test_parse_malformed_json_is_error() -> None:
    result = parse_broker_manifest("{not json")
    assert isinstance(result, BrokerParseError)


def test_parse_non_object_is_error() -> None:
    # A JSON array is valid JSON but not the documented object shape.
    assert isinstance(parse_broker_manifest("[1, 2, 3]"), BrokerParseError)


def test_parse_empty_string_is_error() -> None:
    assert isinstance(parse_broker_manifest(""), BrokerParseError)


def test_parse_deeply_nested_json_degrades_not_crashes() -> None:
    # Deeply-nested JSON (under the io_safe size cap) overflows json's decoder
    # recursion, raising RecursionError (a RuntimeError, not a ValueError). It
    # must degrade to a parse error, never propagate and crash the scan.
    hostile = "[" * 200_000 + "]" * 200_000
    assert isinstance(parse_broker_manifest(hostile), BrokerParseError)


def test_front_with_tilde_matches_absolute_subject() -> None:
    # The documented manifest example writes fronts as "~/.mcp.json#shell", while
    # the trust engine discovers absolute subject ids — the two must match, or a
    # correctly-brokered server falsely reports BROKER-ABSENT.
    priv = _decl("shell", command="node", auto_approve=("run_command",))
    subjects = [("/Users/me/.mcp.json#shell", priv)]
    manifest = _sound(fronts=("~/.mcp.json#shell",))
    findings = check_broker_posture(subjects, manifest, present=True, home="/Users/me")
    assert [f.id for f in findings] == []  # fronted -> no BROKER-ABSENT


def test_parse_unknown_enum_normalizes_to_worse_posture() -> None:
    # Unknown values are tolerated but graded as the WORSE posture (fail-closed).
    raw = json.dumps({"allowlist": "banana", "tool_manifests": "maybe", "audit_log": "sometimes"})
    manifest = parse_broker_manifest(raw)
    assert isinstance(manifest, BrokerManifest)
    assert manifest.allowlist == "wildcard"
    assert manifest.tool_manifests == "unverified"
    assert manifest.audit_log == "off"


def test_parse_missing_posture_fields_normalize_to_worse() -> None:
    manifest = parse_broker_manifest(json.dumps({"schema_version": "1.0"}))
    assert isinstance(manifest, BrokerManifest)
    assert manifest.fronts == ()
    assert (manifest.allowlist, manifest.tool_manifests, manifest.audit_log) == (
        "wildcard",
        "unverified",
        "off",
    )


def test_parse_non_list_fronts_becomes_empty() -> None:
    manifest = parse_broker_manifest(json.dumps({"fronts": "not-a-list"}))
    assert isinstance(manifest, BrokerManifest)
    assert manifest.fronts == ()


def test_parse_never_raises_on_hostile_input() -> None:
    for hostile in ('{"fronts": {"a": 1}}', "123", "null", "true", '"a string"', "\x00\x01"):
        # None of these can crash; each is either a manifest or a parse error.
        assert isinstance(parse_broker_manifest(hostile), (BrokerManifest, BrokerParseError))


# --- is_privileged ----------------------------------------------------------
def test_is_privileged_on_dangerous_autoapprove() -> None:
    assert is_privileged(_decl("s", auto_approve=("run_command",))) is True


def test_is_privileged_on_wildcard_autoapprove() -> None:
    assert is_privileged(_decl("s", auto_approve=("mcp__*",))) is True


def test_is_not_privileged_on_scoped_grants() -> None:
    # A scoped, non-dangerous grant is not privileged (matches scan/trust).
    assert is_privileged(_decl("s", auto_approve=("read_file", "Glob(src/**)"))) is False


def test_is_not_privileged_with_no_autoapprove() -> None:
    assert is_privileged(_decl("s")) is False


# --- routes_through_broker --------------------------------------------------
def test_wrapper_as_command_routes() -> None:
    assert routes_through_broker(_decl("s", command="ianua-atb-pep")) is True


def test_wrapper_with_path_prefix_routes() -> None:
    assert routes_through_broker(_decl("s", command="/usr/local/bin/ianua-atb-pep")) is True


def test_wrapper_windows_path_routes() -> None:
    assert routes_through_broker(_decl("s", command=r"C:\tools\ianua-atb.exe")) is True


def test_runner_with_wrapper_first_arg_routes() -> None:
    assert routes_through_broker(_decl("s", command="npx", args=("ianua-atb-pep",))) is True


def test_plain_runner_does_not_route() -> None:
    assert routes_through_broker(_decl("s", command="npx", args=("-y", "some-server"))) is False


def test_plain_command_does_not_route() -> None:
    assert routes_through_broker(_decl("s", command="node")) is False


def test_no_command_does_not_route() -> None:
    assert routes_through_broker(_decl("s")) is False


# --- check_broker_posture: no manifest (present=False) ----------------------
def test_no_manifest_flags_absent_for_privileged() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    findings = check_broker_posture(subjects, None, present=False)
    assert [f.id for f in findings] == ["BROKER-ABSENT"]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].dimension is Dimension.TOOL_SCOPE


def test_no_manifest_silent_for_non_privileged() -> None:
    subjects = [("cfg#safe", _decl("safe", auto_approve=("read_file",)))]
    assert check_broker_posture(subjects, None, present=False) == []


def test_no_manifest_silent_for_wrapper_routed_privileged() -> None:
    # A privileged server behind the interception wrapper needs no manifest entry.
    subjects = [
        ("cfg#shell", _decl("shell", command="ianua-atb-pep", auto_approve=("run_command",)))
    ]
    assert check_broker_posture(subjects, None, present=False) == []


def test_no_manifest_emits_no_quality_findings() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    ids = {f.id for f in check_broker_posture(subjects, None, present=False)}
    assert ids == {"BROKER-ABSENT"}  # no UNVERIFIED/NO-AUDIT/PERMISSIVE without a manifest


# --- check_broker_posture: the positive (fully-sound) case ------------------
def test_fully_brokered_sound_manifest_is_silent() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = _sound(fronts=("cfg#shell",))
    assert check_broker_posture(subjects, manifest, present=True) == []


def test_wrapper_routed_privileged_with_sound_manifest_is_silent() -> None:
    subjects = [
        ("cfg#shell", _decl("shell", command="ianua-atb-pep", auto_approve=("run_command",)))
    ]
    # Not in fronts, but intercepted at the transport -> not absent, still clean.
    assert check_broker_posture(subjects, _sound(fronts=()), present=True) == []


# --- check_broker_posture: BROKER-ABSENT with a manifest --------------------
def test_privileged_not_in_fronts_flags_absent() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = _sound(fronts=("cfg#other",))  # fronts something else
    ids = [f.id for f in check_broker_posture(subjects, manifest, present=True)]
    assert ids == ["BROKER-ABSENT"]


def test_absent_location_is_the_subject_id() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    findings = check_broker_posture(subjects, None, present=False)
    assert findings[0].location.path == "cfg#shell"


# --- check_broker_posture: manifest-quality findings ------------------------
def test_unverified_fires_when_fronting_a_privileged_server() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = BrokerManifest(
        schema_version="1.0",
        fronts=("cfg#shell",),
        allowlist="least_privilege",
        tool_manifests="unverified",
        audit_log="enabled",
    )
    ids = [f.id for f in check_broker_posture(subjects, manifest, present=True)]
    assert ids == ["BROKER-MANIFEST-UNVERIFIED"]
    assert check_broker_posture(subjects, manifest, present=True)[0].severity is Severity.HIGH


def test_unverified_does_not_fire_without_a_fronted_privileged_server() -> None:
    # tool_manifests unverified, but the privileged server is NOT fronted: the
    # unverified-manifest risk only matters if the manifest actually fronts
    # something privileged. Only BROKER-ABSENT should fire.
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = BrokerManifest(
        schema_version="1.0",
        fronts=(),
        allowlist="least_privilege",
        tool_manifests="unverified",
        audit_log="enabled",
    )
    ids = {f.id for f in check_broker_posture(subjects, manifest, present=True)}
    assert ids == {"BROKER-ABSENT"}


def test_no_audit_fires_on_manifest_present() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = BrokerManifest(
        schema_version="1.0",
        fronts=("cfg#shell",),
        allowlist="least_privilege",
        tool_manifests="signed",
        audit_log="off",
    )
    findings = check_broker_posture(subjects, manifest, present=True)
    assert [f.id for f in findings] == ["BROKER-NO-AUDIT"]
    assert findings[0].severity is Severity.MEDIUM


def test_permissive_allowlist_fires() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = BrokerManifest(
        schema_version="1.0",
        fronts=("cfg#shell",),
        allowlist="wildcard",
        tool_manifests="signed",
        audit_log="enabled",
    )
    findings = check_broker_posture(subjects, manifest, present=True)
    assert [f.id for f in findings] == ["BROKER-ALLOWLIST-PERMISSIVE"]
    assert findings[0].severity is Severity.MEDIUM


def test_worst_case_manifest_fires_every_quality_finding() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = BrokerManifest(
        schema_version="1.0",
        fronts=("cfg#shell",),
        allowlist="wildcard",
        tool_manifests="unverified",
        audit_log="off",
    )
    ids = {f.id for f in check_broker_posture(subjects, manifest, present=True)}
    assert ids == {
        "BROKER-MANIFEST-UNVERIFIED",
        "BROKER-NO-AUDIT",
        "BROKER-ALLOWLIST-PERMISSIVE",
    }
    # The server is fronted, so no BROKER-ABSENT.
    assert "BROKER-ABSENT" not in ids


# --- check_broker_posture: parse error --------------------------------------
def test_parse_error_flags_parse_error_and_absent() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    err = BrokerParseError("bad")
    ids = {f.id for f in check_broker_posture(subjects, err, present=True)}
    # A malformed manifest verifies nothing: PARSE-ERROR plus the privileged
    # server treated as unbrokered.
    assert ids == {"BROKER-PARSE-ERROR", "BROKER-ABSENT"}


def test_parse_error_is_low_severity() -> None:
    err = BrokerParseError("bad")
    findings = check_broker_posture([], err, present=True)
    assert [f.id for f in findings] == ["BROKER-PARSE-ERROR"]
    assert findings[0].severity is Severity.LOW


def test_parse_error_emits_no_quality_findings() -> None:
    # We cannot read allowlist/audit/manifests from a broken file.
    err = BrokerParseError("bad")
    ids = {f.id for f in check_broker_posture([], err, present=True)}
    assert ids == {"BROKER-PARSE-ERROR"}


# --- separator-agnostic subject matching ------------------------------------
def test_fronts_match_is_separator_agnostic() -> None:
    subjects = [(r"C:\configs\.mcp.json#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = _sound(fronts=("C:/configs/.mcp.json#shell",))
    assert check_broker_posture(subjects, manifest, present=True) == []


# --- every finding rides Dimension.TOOL_SCOPE -------------------------------
def test_all_broker_findings_are_tool_scope() -> None:
    subjects = [("cfg#shell", _decl("shell", auto_approve=("run_command",)))]
    manifest = BrokerManifest(
        schema_version="1.0",
        fronts=("cfg#other",),
        allowlist="wildcard",
        tool_manifests="unverified",
        audit_log="off",
    )
    findings = check_broker_posture(subjects, manifest, present=True)
    assert findings  # sanity: several findings present
    assert all(f.dimension is Dimension.TOOL_SCOPE for f in findings)
