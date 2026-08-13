# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Stable JSON renderer (ticket T-302).

Deterministic and byte-stable (sorted keys, no timestamps) so it can be diffed,
golden-tested, and consumed by CI. The raw secret value is never present; the
masked form appears only under ``--show-secrets``.
"""

from __future__ import annotations

import json

from ..domain import Report
from . import RenderOptions, display_path
from .common import ordered_findings, server_grade

TOOL_NAME = "ianua-broker"


def report_to_dict(report: Report, opts: RenderOptions | None = None) -> dict[str, object]:
    """Convert a Report to a JSON-serializable dict (stable shape)."""
    opts = opts or RenderOptions()
    servers: list[dict[str, object]] = []
    for server in report.servers:
        findings: list[dict[str, object]] = []
        for finding in ordered_findings(server):
            entry: dict[str, object] = {
                "id": finding.id,
                "dimension": finding.dimension.value,
                "severity": finding.severity.value,
                "title": finding.title,
                "location": {
                    "path": display_path(finding.location.path, opts),
                    "line": finding.location.line,
                },
                "rationale": finding.rationale,
                "remediation": finding.remediation,
            }
            if finding.secret is not None:
                secret: dict[str, object] = {
                    "sha256_8": finding.secret.sha256_8,
                    "length": finding.secret.length,
                }
                if opts.show_secrets:
                    secret["masked"] = finding.secret.masked
                entry["secret"] = secret
            if finding.acceptance is not None:
                # Optional since schema_version 1.1: a named-human acceptance.
                # "expired" is precomputed by the CLI so this stays byte-stable.
                entry["acceptance"] = {
                    "owner": finding.acceptance.owner,
                    "accepted": finding.acceptance.accepted,
                    "expires": finding.acceptance.expires,
                    "reason": finding.acceptance.reason,
                    "expired": finding.acceptance.expired,
                }
            findings.append(entry)
        servers.append(
            {
                "id": server.id,
                "state": server.state.value,
                "running": server.running,
                "bind_addr": server.bind_addr,
                "port": server.port,
                "inspection_incomplete": server.inspection_incomplete,
                "grade": server_grade(server),
                "findings": findings,
            }
        )

    return {
        "tool": TOOL_NAME,
        "schema_version": report.schema_version,
        "generated_with_online": report.generated_with_online,
        "overall_grade": report.overall_grade,
        "dimension_grades": {dim.value: grade for dim, grade in report.dimension_grades.items()},
        "servers": servers,
    }


def render_json(report: Report, opts: RenderOptions | None = None) -> str:
    """Render a Report as deterministic, byte-stable JSON text."""
    payload = report_to_dict(report, opts)
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
