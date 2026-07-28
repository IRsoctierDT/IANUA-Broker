"""Exposure, tool-scope, pinning, and scoring checks with clean fixtures (T-202/208/209/210/212)."""

from __future__ import annotations

from mcpscan.adapters.base import ServerDecl
from mcpscan.checks.exposure import check_socket_exposure
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
def test_loopback_not_flagged() -> None:
    assert classify_exposure("127.0.0.1") is None
    assert check_socket_exposure(ListeningSocket("127.0.0.1", 8000, 1, "node")) == []


def test_wildcard_bind_is_critical() -> None:
    assert classify_exposure("0.0.0.0") is Severity.CRITICAL
    findings = check_socket_exposure(ListeningSocket("0.0.0.0", 8000, 1, "node"))
    assert findings[0].dimension is Dimension.EXPOSURE


def test_routable_bind_is_critical() -> None:
    # A concrete, parseable, non-loopback address is reachable beyond the host.
    assert classify_exposure("8.8.8.8") is Severity.CRITICAL


def test_unparseable_bind_is_high() -> None:
    # An address we cannot parse is flagged conservatively rather than ignored.
    assert classify_exposure("not-an-ip") is Severity.HIGH


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
    findings = check_socket_exposure(ListeningSocket("0.0.0.0", 1, 1, "n")) * 5
    assert score_findings(findings) == 0
    assert grade_findings(findings) == "F"


def test_worst_grade_and_dimension_grades() -> None:
    assert worst_grade(["A", "C", "F", "B"]) == "F"
    assert worst_grade([]) == "A"
    crit = check_socket_exposure(ListeningSocket("0.0.0.0", 1, 1, "n"))
    grades = dimension_grades(crit)
    assert grades[Dimension.EXPOSURE] == "D"  # one Critical: 100-40=60 => D (rubric)
    assert grades[Dimension.PINNING] == "A"
