# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for renderers: ordering, location, and secret display."""

from __future__ import annotations

from ..domain import Acceptance, Finding, SecretFingerprint, Server
from ..scoring import grade_findings
from . import SEVERITY_ORDER, RenderOptions, display_path


def ordered_findings(server: Server) -> list[Finding]:
    """A server's findings, most-severe first (stable secondary order by id)."""
    return sorted(server.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.id))


def server_grade(server: Server) -> str:
    """The letter grade for a single server."""
    return grade_findings(server.findings)


def location_str(finding: Finding, opts: RenderOptions) -> str:
    """Human location string with path privacy applied."""
    path = display_path(finding.location.path, opts)
    if finding.location.line is not None:
        return f"{path}:{finding.location.line}"
    return path


def secret_str(fp: SecretFingerprint | None, opts: RenderOptions) -> str | None:
    """Render a secret fingerprint, honoring ``--show-secrets`` (never raw)."""
    if fp is None:
        return None
    base = f"len={fp.length} sha256:{fp.sha256_8}"
    if opts.show_secrets:
        return f"{fp.masked} ({base})"
    return f"[redacted {base}]"


def acceptance_str(acceptance: Acceptance) -> str:
    """Render an acceptance annotation — quiet while valid, loud once expired."""
    if acceptance.expired:
        return f"acceptance EXPIRED ({acceptance.owner}, expired {acceptance.expires})"
    base = f"[ACCEPTED until {acceptance.expires} by {acceptance.owner}]"
    return f"{base} — {acceptance.reason}" if acceptance.reason else base
