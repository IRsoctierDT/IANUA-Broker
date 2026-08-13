# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Agent-host logging-health checks (Wave 3 Feature L), pure over its inputs.

Grades the agent-host telemetry/log surfaces named by each host adapter's
registry (``HostAdapter.telemetry_surfaces``). A degraded logging surface is the
silent-failure the report ties to *Impair Defenses* (T1562.003): if the host is
not logging, an attacker's actions on it go uncaptured.

- ``TELEMETRY-ABSENT`` (LOW) — an expected log surface is missing or empty, so
  logging is likely off and adversary activity would leave no trace.
- ``TELEMETRY-PERMS`` (MEDIUM) — a log is group/world-readable, so any other
  local user or process can read (and, with write access, tamper with) the
  audit trail at rest.
- ``TELEMETRY-STALE`` (INFO) — the newest log is far older than "now", a sign
  that logging silently stopped some time ago.

Dimension: these findings ride the ``EXPOSURE`` posture dimension. Logging
health is really a fifth, detection-and-response concern, but adding a new
:class:`Dimension` would change the scan-JSON shape (a new ``dimension_grades``
key) and this wave permits only one such bump — reserved elsewhere — so the
family is mapped onto the existing exposure/observability surface rather than
expanding the schema.

Determinism: every function here is a pure function of its arguments — the I/O
(stat, listdir) lives in the engine, and both "now" and the log's mtime are
integers threaded down from ``cli`` so no clock is read here (nor anywhere
outside ``cli``). Redaction: the check is handed only log *metadata* (presence,
POSIX mode, mtime); log contents are never read, so no sensitive log data can
reach a finding.
"""

from __future__ import annotations

from ..domain import Dimension, Finding, Location, Severity

# A log untouched for this long reads as "logging silently stopped". Thirty days
# matches the default drift-baseline staleness window, so an operator sees one
# consistent notion of "too old" across the tool.
_STALE_AFTER_SECONDS = 30 * 24 * 60 * 60


def _absent_finding(path: str) -> Finding:
    return Finding(
        id="TELEMETRY-ABSENT",
        dimension=Dimension.EXPOSURE,
        severity=Severity.LOW,
        title="Agent-host log surface absent or empty",
        location=Location(path=path),
        remediation=(
            "Enable the host's logging so agent/MCP activity is recorded, then "
            "confirm the expected log location is being written."
        ),
        rationale=(
            "No log is present at the expected location, so logging is likely "
            "off. If the host is compromised, an attacker's actions leave no "
            "captured trace to detect or investigate."
        ),
    )


def _perms_finding(path: str) -> Finding:
    return Finding(
        id="TELEMETRY-PERMS",
        dimension=Dimension.EXPOSURE,
        severity=Severity.MEDIUM,
        title="Agent-host log is group/world-readable",
        location=Location(path=path),
        remediation="Restrict permissions: chmod 600 the log file(s).",
        rationale=(
            "Any other local user or process can read the audit trail at rest — "
            "and, with write access, tamper with it — undermining the log as a "
            "record of what the agent (or an attacker) did."
        ),
    )


def _stale_finding(path: str) -> Finding:
    return Finding(
        id="TELEMETRY-STALE",
        dimension=Dimension.EXPOSURE,
        severity=Severity.INFO,
        title="Agent-host log is stale",
        location=Location(path=path),
        remediation=(
            "Check that the host's logging is still running; a log that stopped "
            "updating captures nothing about recent activity."
        ),
        rationale=(
            "The newest log entry is far in the past, a sign that logging "
            "silently stopped — recent agent/attacker activity would not be "
            "recorded."
        ),
    )


def check_telemetry(
    path: str,
    present: bool,
    mode: int | None,
    mtime_epoch: int | None,
    now_epoch: int | None,
    *,
    stale_after_seconds: int = _STALE_AFTER_SECONDS,
) -> list[Finding]:
    """Grade one agent-host telemetry/log surface from already-gathered facts.

    Args:
        path: The log surface's path (for the finding location).
        present: Whether a non-empty log surface actually exists. The engine
            folds "missing" and "exists but empty" into a single ``False`` — both
            mean logging is not capturing anything.
        mode: POSIX permission bits of the log(s) (``st_mode & 0o777``), or
            ``None`` if unknown / off POSIX. When a directory holds several logs
            the engine passes the OR of the child modes, so a single readable log
            trips the perms rule without the directory's own mode misleading it.
        mtime_epoch: The newest log's mtime (seconds since the epoch), or ``None``
            if unknown.
        now_epoch: "Now" in seconds since the epoch, supplied by ``cli`` so this
            check reads no clock. Required to grade staleness; when ``None`` the
            stale rule is simply skipped.
        stale_after_seconds: Age past which a log counts as stale (default 30d).

    Returns:
        ``TELEMETRY-ABSENT`` (LOW) when the surface is absent/empty; otherwise
        ``TELEMETRY-PERMS`` (MEDIUM) when a log is group/world-readable and
        ``TELEMETRY-STALE`` (INFO) when the newest log is older than the staleness
        window. A present, owner-only, fresh log yields no finding.
    """
    if not present:
        return [_absent_finding(path)]
    findings: list[Finding] = []
    if mode is not None and mode & 0o077:
        findings.append(_perms_finding(path))
    if (
        mtime_epoch is not None
        and now_epoch is not None
        and now_epoch - mtime_epoch > stale_after_seconds
    ):
        findings.append(_stale_finding(path))
    return findings
