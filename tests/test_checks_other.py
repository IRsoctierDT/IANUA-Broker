# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Exposure, tool-scope, pinning, and scoring checks with clean fixtures (T-202/208/209/210/212)."""

from __future__ import annotations

import pytest

from mcpscan.adapters.base import ServerDecl
from mcpscan.checks.exposure import ListenerIdentity, check_socket_exposure
from mcpscan.checks.pinning import check_server_pinning
from mcpscan.checks.tool_scope import check_permissions, check_server_auto_approve
from mcpscan.discovery.sockets import ListeningSocket, classify_exposure
from mcpscan.domain import Dimension, Severity
from mcpscan.scoring import (
    dimension_grades,
    grade_findings,
    grade_for_score,
    score_findings,
    worst_grade,
)


# --- exposure ---
def _verified_mcp(sock: ListeningSocket) -> list[object]:
    return check_socket_exposure(
        sock,
        identity=ListenerIdentity.VERIFIED_MCP,
        identity_evidence="synthetic MCP protocol evidence",
    )


def test_loopback_not_flagged() -> None:
    assert classify_exposure("127.0.0.1") is None
    assert _verified_mcp(ListeningSocket("127.0.0.1", 8000, 1, "node")) == []


def test_wildcard_bind_is_critical() -> None:
    assert classify_exposure("0.0.0.0") is Severity.CRITICAL
    findings = _verified_mcp(ListeningSocket("0.0.0.0", 8000, 1, "node"))
    assert findings[0].dimension is Dimension.EXPOSURE
    assert findings[0].severity is Severity.CRITICAL
    # Verified MCP identity allows the severity-bearing exposure finding.
    assert "Verified MCP server" in findings[0].title
    assert "wildcard bind" in findings[0].title
    assert "actual external reachability" in findings[0].rationale


def test_private_lan_bind_is_high_and_names_the_tier() -> None:
    # A private-LAN bind is reachable on the local network — HIGH, not CRITICAL.
    assert classify_exposure("192.168.1.10") is Severity.HIGH
    findings = _verified_mcp(ListeningSocket("192.168.1.10", 3000, 1, "node"))
    assert findings[0].severity is Severity.HIGH
    assert "private-LAN bind" in findings[0].title
    assert "Verified MCP server" in findings[0].title


def test_routable_bind_is_critical() -> None:
    # A concrete, parseable, non-loopback global address is reachable from any network.
    assert classify_exposure("8.8.8.8") is Severity.CRITICAL
    findings = _verified_mcp(ListeningSocket("8.8.8.8", 3000, 1, "node"))
    assert findings[0].severity is Severity.CRITICAL
    assert "public-routable bind" in findings[0].title


def test_unparseable_bind_is_critical() -> None:
    # An address we cannot parse is flagged conservatively as public-routable.
    assert classify_exposure("not-an-ip") is Severity.CRITICAL


def test_regression_non_mcp_ssh_listener_is_not_promoted_to_mcp() -> None:
    """Port 22 + wildcard bind remains visible but SSH evidence blocks an MCP claim."""
    findings = check_socket_exposure(
        ListeningSocket("0.0.0.0", 22, 1, "systemd"),
        identity=ListenerIdentity.NON_MCP,
        identity_evidence="systemd ssh.socket -> ssh.service",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "LISTENER-OBSERVED"
    assert finding.severity is Severity.INFO
    assert "MCP server" not in finding.title
    assert "ssh.socket -> ssh.service" in finding.rationale


def test_regression_unknown_listener_remains_visible_without_identity_claims() -> None:
    """An unknown non-loopback service is observed, not invented into an MCP server."""
    findings = check_socket_exposure(
        ListeningSocket("0.0.0.0", 7777, 4242, "mystery"),
        identity=ListenerIdentity.UNKNOWN,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "LISTENER-OBSERVED"
    assert finding.severity is Severity.INFO
    assert "Unverified listener" in finding.title
    assert "MCP server" not in finding.title
    assert "does not establish MCP identity, Internet reachability, or missing authentication" in finding.rationale


def test_regression_verified_mcp_on_port_22_still_gets_exposure_finding() -> None:
    """Port number never becomes an allow/deny rule: verified MCP on 22 still fires."""
    findings = check_socket_exposure(
        ListeningSocket("0.0.0.0", 22, 9001, "node"),
        identity=ListenerIdentity.VERIFIED_MCP,
        identity_evidence="GET /mcp returned HTTP 405",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "EXPOSE-BIND"
    assert finding.severity is Severity.CRITICAL
    assert finding.location.path == "0.0.0.0:22"
    assert "Verified MCP server" in finding.title
    assert "GET /mcp returned HTTP 405" in finding.rationale


@pytest.mark.parametrize("ip", ["0.0.0.0", "::"])
def test_regression_verified_mcp_ipv4_ipv6_wildcards_are_equivalent(ip: str) -> None:
    """Both wildcard address families retain the same verified-MCP exposure policy."""
    findings = check_socket_exposure(
        ListeningSocket(ip, 8199, 77, "node"),
        identity=ListenerIdentity.VERIFIED_MCP,
        identity_evidence="synthetic MCP handshake",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "EXPOSE-BIND"
    assert finding.severity is Severity.CRITICAL
    assert "wildcard bind" in finding.title
    assert "reachable from any network" not in finding.title
    assert "actual external reachability" in finding.rationale


# --- tool scope ---
def test_dangerous_allow_is_high() -> None:
    findings = check_permissions(("Bash(*)",), "/cfg.json")
    assert findings[0].severity is Severity.HIGH


def test_wildcard_allow_is_medium() -> None:
    findings = check_permissions(("mcp__*",), "/cfg.json")
    assert findings[0].severity is Severity.MEDIUM


def test_clean_permissions_no_findings() -> None:
    assert check_permissions(("Read", "Glob(src/**)"), "/cfg.json") == []


def test_server_auto_approve_dangerous() -> None:
    s = ServerDecl(name="x", command="node", auto_approve=("run_command",))
    assert check_server_auto_approve(s, "/cfg.json")[0].severity is Severity.HIGH


# --- pinning ---
def test_unpinned_npx_flagged() -> None:
    s = ServerDecl(name="x", command="npx", args=("-y", "some-mcp-server"))
    assert check_server_pinning(s, "/cfg.json")[0].dimension is Dimension.PINNING


def test_pinned_npx_clean() -> None:
    s = ServerDecl(name="x", command="npx", args=("-y", "some-mcp-server@1.2.3"))
    assert check_server_pinning(s, "/cfg.json") == []


def test_latest_tag_flagged() -> None:
    s = ServerDecl(name="x", command="npx", args=("some-mcp-server@latest",))
    assert check_server_pinning(s, "/cfg.json")


def test_non_runner_command_clean() -> None:
    s = ServerDecl(name="x", command="/usr/local/bin/my-server", args=())
    assert check_server_pinning(s, "/cfg.json") == []


def test_runner_with_only_flags_has_no_package_to_flag() -> None:
    # A floating runner (npx) invoked with only option flags names no package,
    # so there is nothing to pin and the check stays silent.
    s = ServerDecl(name="x", command="npx", args=("-y",))
    assert check_server_pinning(s, "/cfg.json") == []


# --- scoring ---
def test_scoring_rubric_bands() -> None:
    assert grade_for_score(100) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(59) == "F"


def test_score_floors_at_zero() -> None:
    findings = _verified_mcp(ListeningSocket("0.0.0.0", 1, 1, "n")) * 5
    assert score_findings(findings) == 0
    assert grade_findings(findings) == "F"


def test_worst_grade_and_dimension_grades() -> None:
    assert worst_grade(["A", "C", "F", "B"]) == "F"
    assert worst_grade([]) == "A"
    crit = _verified_mcp(ListeningSocket("0.0.0.0", 1, 1, "n"))
    grades = dimension_grades(crit)
    assert grades[Dimension.EXPOSURE] == "D"  # one Critical: 100-40=60 => D (rubric)
    assert grades[Dimension.PINNING] == "A"
