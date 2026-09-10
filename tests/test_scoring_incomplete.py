# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Incomplete-inspection grade cap."""

from __future__ import annotations

from mcpscan.domain import Dimension, Finding, Location, Server, ServerState, Severity
from mcpscan.scoring import grade_findings, grade_server


def _finding() -> Finding:
    return Finding(
        id="CONFIG-UNREADABLE",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.MEDIUM,
        title="unreadable",
        location=Location(path="x"),
        remediation="fix",
        rationale="r",
    )


def test_incomplete_caps_clean_findings_at_c() -> None:
    server = Server(
        id="s",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        inspection_incomplete=True,
        findings=(),
    )
    assert grade_findings(()) == "A"
    assert grade_server(server) == "C"


def test_complete_empty_stays_a() -> None:
    server = Server(
        id="s",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        inspection_incomplete=False,
        findings=(),
    )
    assert grade_server(server) == "A"
