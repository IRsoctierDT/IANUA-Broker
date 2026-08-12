# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Alert emission layer (Wave 2 Feature E): findings that ARRIVE, not just print.

The log-to-alert gap: a scan that only prints a report is invisible to anyone
not reading the terminal. This module is the one place that turns a scan/diff
result into an alert on a sink an operator actually watches — ONE versioned
payload, ONE set of sinks, ONE egress gate.

Determinism: :func:`build_emit_payload` is a pure function of its inputs. It
reads no clock (``generated_at`` is computed once in ``cli`` and passed in) and
touches no I/O, so identical inputs always produce an identical payload.

Redaction: the payload carries only REDACTED findings. A detected secret is
present solely as its 8-hex ``sha256_8`` triage handle — never the masked
preview, never the raw value — so the payload upholds the same no-raw-secret
guarantee (architecture R1) as every renderer. There is no ``--show-secrets``
path here: an alert bound for a webhook or a shared log is always fully redacted.

Gating: the three sinks are the only I/O and every one of them is OPT-IN,
selected by ``--emit`` on the CLI and never run by default:
  * :func:`emit_ndjson` appends one JSON line to a file (a WRITE);
  * :func:`emit_webhook` POSTs the payload over HTTP(S) (EGRESS — the CLI
    discloses the destination host to stderr before it fires, and a redirect
    that would downgrade the transport off HTTPS is refused, not followed);
  * :func:`emit_syslog` hands the payload to the local syslog daemon.
Each sink swallows its own failure (warns to stderr, never raises), so a broken
alert channel can never crash the scan it is reporting on.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from http.client import HTTPMessage
from pathlib import Path
from typing import IO

from .domain import Finding, Report, Severity
from .drift.model import DriftReport

# The emitter payload owns its own version line (Wave 2 schema coordination):
# the scan/trust/drift schemas are unchanged, and this is a brand-new object.
EMIT_SCHEMA_VERSION = "1.0"

TOOL_NAME = "ai-agentic-mcpscan"

# Short by design: an alert channel must fail fast, not block a scan on a hung
# endpoint. The scan has already rendered by the time a sink runs.
_DEFAULT_TIMEOUT = 5.0


def _location(finding: Finding) -> str:
    """The finding's location as a single string (``path`` or ``path:line``)."""
    if finding.location.line is not None:
        return f"{finding.location.path}:{finding.location.line}"
    return finding.location.path


def _finding_obj(finding: Finding) -> dict[str, object]:
    """A finding reduced to a redacted, JSON-safe alert object.

    ``sha256_8`` is the only trace of any secret — the masked preview and the
    raw value never appear, so this object is safe to POST or log anywhere.
    """
    return {
        "id": finding.id,
        "dimension": finding.dimension.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "location": _location(finding),
        "sha256_8": finding.secret.sha256_8 if finding.secret is not None else None,
    }


def _scan_body(report: Report) -> dict[str, object]:
    """The scan-specific half of the payload: grades, severity counts, findings."""
    findings = [f for s in report.servers for f in s.findings]
    counts = {sev.value: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    # Most-severe first, then a stable secondary order — deterministic output.
    ordered = sorted(findings, key=lambda f: (-f.severity.weight, f.id, _location(f)))
    return {
        "summary": {
            "overall_grade": report.overall_grade,
            "dimension_grades": {
                dim.value: grade for dim, grade in report.dimension_grades.items()
            },
            "counts": counts,
            "total": len(findings),
        },
        "findings": [_finding_obj(f) for f in ordered],
    }


def _drift_body(report: DriftReport) -> dict[str, object]:
    """The diff-specific half: each drift entry with its Wave 1 degradation cause."""
    entries = [
        {
            "change": entry.change.value,
            "kind": entry.kind.value,
            "key": entry.key,
            "summary": entry.summary,
            "direction": entry.direction.value,
            "cause": entry.cause.value,
        }
        for entry in report.entries
    ]
    return {
        "summary": {
            "total": len(report.entries),
            "regressions": len(report.regressions),
            "improvements": len(report.improvements),
        },
        "drift": entries,
    }


def build_emit_payload(
    report: Report | DriftReport,
    *,
    kind: str,
    generated_at: str,
    gate_failed: bool,
    threshold: str,
) -> dict[str, object]:
    """Build the versioned, redacted alert payload for a scan or diff (pure).

    Args:
        report: The scan :class:`~mcpscan.domain.Report` (``kind="scan"``) or the
            :class:`~mcpscan.drift.model.DriftReport` (``kind="diff"``) to alert on.
        kind: ``"scan"`` or ``"diff"`` — labels the payload for the consumer.
        generated_at: The wall-clock time of the run, computed once in ``cli`` and
            passed in so this function stays clock-free and deterministic.
        gate_failed: Whether the run's CI gate failed (the actionable bit).
        threshold: The gate configuration in effect (scan: the ``--fail-on``
            severity; diff: ``"regression"``/``"none"``), for the consumer's context.

    Returns:
        A JSON-safe dict carrying only redacted findings (``sha256_8`` at most,
        never a raw or masked secret) — identical for identical inputs.
    """
    payload: dict[str, object] = {
        "emit_schema_version": EMIT_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "kind": kind,
        "generated_at": generated_at,
        "gate_failed": gate_failed,
        "threshold": threshold,
    }
    body = _scan_body(report) if isinstance(report, Report) else _drift_body(report)
    payload.update(body)
    return payload


def _dump(payload: Mapping[str, object]) -> str:
    """Serialize a payload to a deterministic, byte-stable JSON string."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def emit_ndjson(path: Path, payload: Mapping[str, object]) -> None:
    """Append the payload to ``path`` as one JSON line (a WRITE; opt-in).

    Newline-delimited JSON so an alert log accumulates one run per line. The file
    is created owner-only (0600) — an alert log names findings and must not be
    left world-readable. Any write error is swallowed with a stderr warning: a
    failed alert must not crash the scan.
    """
    line = _dump(payload) + "\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(line)
        finally:
            try:
                os.chmod(path, 0o600)
            except OSError:  # pragma: no cover - non-POSIX best effort
                pass
    except OSError as exc:
        print(f"warning: --emit ndjson to {path} failed: {exc}", file=sys.stderr)


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow a downgrade to a non-HTTPS URL.

    A webhook endpoint that 30x-redirects the POST to ``http://`` (or any other
    scheme) would defeat the transport guarantee, so the redirect is dropped
    rather than followed — a redacted alert is never re-sent in the clear.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _post(request: urllib.request.Request, timeout: float) -> None:
    """The single egress primitive (injected in tests, never hit live).

    Uses an opener whose only redirect handler refuses HTTPS downgrades. The
    scheme is validated by the caller before this is reached.
    """
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    with opener.open(request, timeout=timeout):  # nosec B310 (scheme pre-validated http/https; no downgrade redirects)
        pass


def emit_webhook(
    url: str, payload: Mapping[str, object], *, timeout: float = _DEFAULT_TIMEOUT
) -> None:
    """POST the payload as JSON to ``url`` (EGRESS; opt-in, disclosed by the CLI).

    Only ``http``/``https`` URLs are accepted; any other scheme is refused
    without a request. A redirect that would downgrade off HTTPS is dropped
    (see :class:`_HttpsOnlyRedirect`). Any network error is swallowed with a
    stderr warning — a failed alert must never crash the scan. The body is the
    same fully-redacted payload every other sink sees; no secret value is sent.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        print(
            f"warning: --emit webhook refused non-HTTP(S) URL scheme {scheme!r}; nothing sent.",
            file=sys.stderr,
        )
        return
    data = _dump(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        _post(request, timeout)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"warning: --emit webhook POST failed: {exc}", file=sys.stderr)


def emit_syslog(payload: Mapping[str, object]) -> None:
    """Send the payload as one line to the local syslog daemon (opt-in).

    Local, but still opt-in like every sink. Uses a stdlib
    :class:`logging.handlers.SysLogHandler`; any error reaching the daemon is
    swallowed with a stderr warning so a missing/again-unreachable syslog socket
    cannot crash the scan.
    """
    line = _dump(payload)
    handler: logging.handlers.SysLogHandler | None = None
    try:
        handler = logging.handlers.SysLogHandler()
        record = logging.LogRecord(
            name="mcpscan",
            level=logging.WARNING,
            pathname=__file__,
            lineno=0,
            msg=line,
            args=(),
            exc_info=None,
        )
        handler.emit(record)
    except (OSError, ValueError) as exc:
        print(f"warning: --emit syslog failed: {exc}", file=sys.stderr)
    finally:
        if handler is not None:
            try:
                handler.close()
            except OSError:  # pragma: no cover - best effort
                pass
