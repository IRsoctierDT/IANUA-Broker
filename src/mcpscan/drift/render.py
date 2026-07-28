# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Drift renderers: terminal and stable JSON for a DriftReport."""

from __future__ import annotations

import json

from .model import ChangeType, Direction, DriftEntry, DriftReport

_CHANGE_MARK: dict[ChangeType, str] = {
    ChangeType.ADDED: "+",
    ChangeType.REMOVED: "-",
    ChangeType.CHANGED: "~",
}

_DIRECTION_LABEL: dict[Direction, str] = {
    Direction.REGRESSION: "REGRESSION",
    Direction.IMPROVEMENT: "improvement",
    Direction.INFORMATIONAL: "info",
}


def render_terminal_drift(report: DriftReport) -> str:
    """Human-readable drift, regressions first."""
    n_reg = len(report.regressions)
    n_imp = len(report.improvements)
    lines = [
        (
            f"AI Agentic MCPscan — drift: {len(report.entries)} change(s) "
            f"({n_reg} regression(s), {n_imp} improvement(s))"
        )
    ]
    if not report.has_drift:
        lines.append("  No drift from baseline.")
        return "\n".join(lines) + "\n"

    for entry in report.entries:
        mark = _CHANGE_MARK[entry.change]
        label = _DIRECTION_LABEL[entry.direction]
        lines.append(f"  {mark} [{label:11}] {entry.summary}")
        if entry.change is ChangeType.CHANGED:
            before = dict(entry.detail_before)
            after = dict(entry.detail_after)
            for field_name in sorted(set(before) | set(after)):
                b, a = before.get(field_name, "∅"), after.get(field_name, "∅")
                if b != a:
                    lines.append(f"      {field_name}: {b} → {a}")
    return "\n".join(lines) + "\n"


def _entry_to_dict(entry: DriftEntry) -> dict[str, object]:
    return {
        "change": entry.change.value,
        "kind": entry.kind.value,
        "key": entry.key,
        "summary": entry.summary,
        "direction": entry.direction.value,
        "detail_before": dict(entry.detail_before),
        "detail_after": dict(entry.detail_after),
    }


def render_json_drift(report: DriftReport) -> str:
    """Stable, machine-readable drift JSON."""
    payload = {
        "schema_version": "1.0",
        "summary": {
            "total": len(report.entries),
            "regressions": len(report.regressions),
            "improvements": len(report.improvements),
        },
        "entries": [_entry_to_dict(e) for e in report.entries],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
