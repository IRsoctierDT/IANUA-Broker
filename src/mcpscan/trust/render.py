# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Trust renderers: terminal (risky subjects first) and stable JSON."""

from __future__ import annotations

import json

from ..report import RenderOptions, display_path
from .model import TrustProfile, TrustReport


def render_terminal_trust(report: TrustReport, opts: RenderOptions) -> str:
    """Human-readable trust report, lowest Trust Score first."""
    n_risky = len(report.risky)
    lines = [
        (
            f"AI Agentic MCPscan — agent trust: {len(report.profiles)} tool(s), "
            f"overall {report.overall_grade}; {n_risky} with risk relationship(s)"
        )
    ]
    if not report.profiles:
        lines.append("  No MCP servers found to analyze.")
        return "\n".join(lines) + "\n"

    for profile in sorted(report.profiles, key=lambda p: (p.score, p.subject)):
        where = display_path(profile.location, opts)
        lines.append("")
        lines.append(
            f"▶ {profile.server_name!r} [{profile.host}]  "
            f"Trust {profile.score}/100 (grade {profile.grade})"
        )
        lines.append(f"    where: {where}")
        for factor in profile.present_factors:
            lines.append(f"    · {factor.factor.value}: {factor.detail} (+{factor.risk} risk)")
        for rel in profile.relationships:
            lines.append(f"    ⚠ {rel.id}: {rel.title}")
            lines.append(f"        {rel.rationale}")
    return "\n".join(lines) + "\n"


def _profile_to_dict(profile: TrustProfile, opts: RenderOptions) -> dict[str, object]:
    return {
        "subject": profile.subject,
        "server_name": profile.server_name,
        "host": profile.host,
        "location": display_path(profile.location, opts),
        "score": profile.score,
        "grade": profile.grade,
        "factors": [
            {"factor": f.factor.value, "risk": f.risk, "detail": f.detail, "present": f.present}
            for f in profile.factors
        ],
        "relationships": [
            {
                "id": r.id,
                "title": r.title,
                "rationale": r.rationale,
                "factors": [fac.value for fac in r.factors],
            }
            for r in profile.relationships
        ],
    }


def render_json_trust(report: TrustReport, opts: RenderOptions) -> str:
    """Stable, machine-readable trust JSON."""
    payload = {
        "schema_version": report.schema_version,
        "overall_grade": report.overall_grade,
        "profiles": [_profile_to_dict(p, opts) for p in report.profiles],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
