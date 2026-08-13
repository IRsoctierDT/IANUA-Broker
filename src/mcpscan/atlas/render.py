# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Atlas renderers: framework-annotated findings and the reference matrix.

Two views:

- **annotated** — a scan's findings, each carrying its framework citations
  (what an assessor pastes into a report).
- **matrix** — the full static check-id → framework reference table, no scan
  needed (what a reviewer audits).

Pure functions over the frozen domain + mapping models, same conventions as the
scan renderers (path relativization, stable JSON).
"""

from __future__ import annotations

import json

from ..domain import Report
from ..report import RenderOptions, display_path
from .model import MAPPINGS, FrameworkRef, framework_label, refs_for


def _ref_line(ref: FrameworkRef) -> str:
    return f"{framework_label(ref.framework)} {ref.ref} — {ref.title}"


def render_terminal_atlas(report: Report, opts: RenderOptions) -> str:
    """The scan's findings, each annotated with its framework citations."""
    total = sum(len(s.findings) for s in report.servers)
    lines = [f"IANUA-Broker — atlas: {total} finding(s) mapped"]

    if total == 0:
        lines.append("  No findings — nothing to map.")
        return "\n".join(lines) + "\n"

    for server in report.servers:
        if not server.findings:
            continue
        lines.append("")
        lines.append(f"▶ {display_path(server.id, opts)}")
        for finding in server.findings:
            lines.append(f"  [{finding.severity.value.upper():8}] {finding.id}: {finding.title}")
            refs = refs_for(finding.id)
            if not refs:
                lines.append("             (no framework mapping)")
            for ref in refs:
                lines.append(f"             ↳ {_ref_line(ref)}")
    return "\n".join(lines) + "\n"


def render_terminal_matrix() -> str:
    """The full static reference matrix (no scan involved)."""
    lines = ["IANUA-Broker — atlas reference matrix"]
    for check_id in sorted(MAPPINGS):
        lines.append("")
        lines.append(f"▶ {check_id}")
        for ref in MAPPINGS[check_id]:
            lines.append(f"  {_ref_line(ref)}")
    return "\n".join(lines) + "\n"


def _ref_to_dict(ref: FrameworkRef) -> dict[str, str]:
    return {
        "framework": ref.framework.value,
        "framework_label": framework_label(ref.framework),
        "ref": ref.ref,
        "title": ref.title,
    }


def render_json_atlas(report: Report, opts: RenderOptions) -> str:
    """Stable JSON: mapped findings plus the full matrix for reference."""
    findings = [
        {
            "id": f.id,
            "severity": f.severity.value,
            "title": f.title,
            "server": display_path(s.id, opts),
            "location": display_path(f.location.path, opts),
            "mappings": [_ref_to_dict(r) for r in refs_for(f.id)],
        }
        for s in report.servers
        for f in s.findings
    ]
    payload = {
        "schema_version": "1.0",
        "findings": findings,
        "matrix": {cid: [_ref_to_dict(r) for r in refs] for cid, refs in sorted(MAPPINGS.items())},
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
