# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Human-readable terminal renderer (ticket T-301)."""

from __future__ import annotations

from ..domain import Report, Severity
from . import RenderOptions
from .common import acceptance_str, location_str, ordered_findings, secret_str, server_grade

_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def render_terminal(report: Report, opts: RenderOptions | None = None) -> str:
    """Render a Report as a severity-ordered plain-text summary."""
    opts = opts or RenderOptions()
    lines: list[str] = []
    lines.append(f"AI Agentic MCPscan — overall posture: {report.overall_grade}")

    dims = ", ".join(
        f"{dim.value}={grade}"
        for dim, grade in sorted(report.dimension_grades.items(), key=lambda kv: kv[0].value)
    )
    if dims:
        lines.append(f"  dimensions: {dims}")

    all_findings = [f for s in report.servers for f in s.findings]
    if not all_findings:
        lines.append("")
        lines.append("No findings. Your scanned MCP setup looks clean. ✅")
        return "\n".join(lines) + "\n"

    counts = {sev: 0 for sev in Severity}
    for finding in all_findings:
        counts[finding.severity] += 1
    summary = ", ".join(
        f"{counts[sev]} {_SEV_LABEL[sev].lower()}" for sev in Severity if counts[sev]
    )
    lines.append(f"  findings: {summary}")
    if any(f.acceptance is not None for f in all_findings):
        # Gate-vs-grade distinction, stated where the operator reads the grade.
        lines.append(
            "  note: accepted findings still lower the grade; they only stop failing the gate."
        )

    for server in report.servers:
        if not server.findings:
            continue
        lines.append("")
        flag = " (inspection incomplete)" if server.inspection_incomplete else ""
        lines.append(f"▶ {server.id}  [grade {server_grade(server)}]{flag}")
        for finding in ordered_findings(server):
            loc = location_str(finding, opts)
            lines.append(f"  [{_SEV_LABEL[finding.severity]:8}] {finding.title}")
            if finding.acceptance is not None:
                lines.append(f"             accept: {acceptance_str(finding.acceptance)}")
            lines.append(f"             where: {loc}")
            secret = secret_str(finding.secret, opts)
            if secret is not None:
                lines.append(f"             secret: {secret}")
            lines.append(f"             why:   {finding.rationale}")
            lines.append(f"             fix:   {finding.remediation}")

    return "\n".join(lines) + "\n"
