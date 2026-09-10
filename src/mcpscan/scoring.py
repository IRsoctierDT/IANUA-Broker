# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Deterministic posture scoring (ticket T-210, SPEC §6).

Pure functions: identical findings always yield identical grades. Each server
starts at 100, loses points per finding by severity weight, and maps to A-F.

Incomplete inspection cannot grade clean: an ``inspection_incomplete`` server
is capped at **C** so a surface never inspected cannot claim A/B.
"""

from __future__ import annotations

from collections.abc import Iterable

from .domain import Dimension, Finding, Server

_MAX_SCORE = 100
_GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
)
_FAIL_GRADE = "F"
# Cap when the scanner could not fully inspect the server (CONFIG-UNREADABLE,
# permission-denied sockets, malformed broker manifest, …). A/B would imply a
# completed audit the operator did not get.
_INCOMPLETE_CAP = "C"
_GRADE_ORDER = "ABCDEF"


def score_findings(findings: Iterable[Finding]) -> int:
    """Return a 0-100 score for a set of findings (floored at 0)."""
    score = _MAX_SCORE - sum(f.severity.weight for f in findings)
    return max(0, score)


def grade_for_score(score: int) -> str:
    """Map a 0-100 score to an A-F letter grade."""
    for threshold, letter in _GRADE_BANDS:
        if score >= threshold:
            return letter
    return _FAIL_GRADE


def grade_findings(findings: Iterable[Finding]) -> str:
    """Convenience: grade a set of findings directly."""
    return grade_for_score(score_findings(list(findings)))


def _cap_grade(grade: str, cap: str) -> str:
    """Return the worse of ``grade`` and ``cap`` (A best … F worst)."""
    return grade if _GRADE_ORDER.index(grade) >= _GRADE_ORDER.index(cap) else cap


def grade_server(server: Server) -> str:
    """Grade one server; incomplete inspection cannot score above C."""
    grade = grade_findings(server.findings)
    if server.inspection_incomplete:
        return _cap_grade(grade, _INCOMPLETE_CAP)
    return grade


def worst_grade(grades: Iterable[str]) -> str:
    """Return the worst (highest-letter) grade in the set; 'A' if empty."""
    letters = list(grades)
    if not letters:
        return "A"
    return max(letters)  # 'F' > 'D' > ... > 'A' lexicographically


def dimension_grades(findings: Iterable[Finding]) -> dict[Dimension, str]:
    """Per-dimension grade over the given findings."""
    by_dim: dict[Dimension, list[Finding]] = {dim: [] for dim in Dimension}
    for finding in findings:
        by_dim[finding.dimension].append(finding)
    return {dim: grade_findings(items) for dim, items in by_dim.items()}
