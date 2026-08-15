# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Drift renderers: terminal and stable JSON for a DriftReport.

Each entry carries its :class:`DriftCause` — terminal as a short tag like
``[exposure-drift]``, JSON as ``"cause": "exposure_drift"`` — so readers see
*why* posture drifted, not just that it did. When the caller supplies a
:class:`StalenessVerdict`, both renderers also report the baseline's validation
age ("last validated N days ago"), warning when it exceeds the accepted cadence.
"""

from __future__ import annotations

import json

from ..report import inert_text
from .model import ChangeType, Direction, DriftEntry, DriftReport
from .staleness import StalenessVerdict

# The drift-JSON payload shape (distinct from the baseline DRIFT_SCHEMA_VERSION).
# 1.1: entries gained a "cause" key (the degradation-cause vocabulary), and the
# payload gained "baseline_created_at" / "baseline_age_days" / "stale"
# (validation-age staleness).
_DRIFT_JSON_SCHEMA_VERSION = "1.1"

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


def _cause_tag(entry: DriftEntry) -> str:
    return entry.cause.value.replace("_", "-")


def _staleness_lines(verdict: StalenessVerdict) -> list[str]:
    """The validation-age line, plus a cadence warning when the age is stale."""
    if verdict.created_date is None or verdict.age_days is None:
        return ["baseline created: unknown (no created_at metadata) — cannot assess staleness"]
    unit = "day" if verdict.age_days == 1 else "days"
    lines = [f"baseline created {verdict.created_date.isoformat()} — {verdict.age_days} {unit} ago"]
    if verdict.stale:
        lines.append(
            f"warning: baseline is stale ({verdict.age_days} {unit} old, max "
            f"{verdict.max_age_days}) — posture decays without re-validation; "
            "strong performance is rented, not owned"
        )
    return lines


def render_terminal_drift(report: DriftReport, *, staleness: StalenessVerdict | None = None) -> str:
    """Human-readable drift, regressions first, with the baseline's validation age."""
    n_reg = len(report.regressions)
    n_imp = len(report.improvements)
    lines = [
        (
            f"IANUA-Broker — drift: {len(report.entries)} change(s) "
            f"({n_reg} regression(s), {n_imp} improvement(s))"
        )
    ]
    if staleness is not None:
        lines.extend(_staleness_lines(staleness))
    if not report.has_drift:
        lines.append("  No drift from baseline.")
        return "\n".join(lines) + "\n"

    for entry in report.entries:
        mark = _CHANGE_MARK[entry.change]
        label = _DIRECTION_LABEL[entry.direction]
        lines.append(f"  {mark} [{label:11}] [{_cause_tag(entry)}] {inert_text(entry.summary)}")
        if entry.change is ChangeType.CHANGED:
            before = dict(entry.detail_before)
            after = dict(entry.detail_after)
            for field_name in sorted(set(before) | set(after)):
                b, a = before.get(field_name, "∅"), after.get(field_name, "∅")
                if b != a:
                    lines.append(
                        f"      {inert_text(field_name)}: {inert_text(b)} → {inert_text(a)}"
                    )
    return "\n".join(lines) + "\n"


def _entry_to_dict(entry: DriftEntry) -> dict[str, object]:
    return {
        "change": entry.change.value,
        "kind": entry.kind.value,
        "key": entry.key,
        "summary": entry.summary,
        "direction": entry.direction.value,
        "cause": entry.cause.value,
        "detail_before": dict(entry.detail_before),
        "detail_after": dict(entry.detail_after),
    }


def render_json_drift(report: DriftReport, *, staleness: StalenessVerdict | None = None) -> str:
    """Stable, machine-readable drift JSON (with the baseline's validation age)."""
    payload = {
        "schema_version": _DRIFT_JSON_SCHEMA_VERSION,
        "baseline_created_at": None if staleness is None else staleness.created_at,
        "baseline_age_days": None if staleness is None else staleness.age_days,
        "stale": False if staleness is None else staleness.stale,
        "summary": {
            "total": len(report.entries),
            "regressions": len(report.regressions),
            "improvements": len(report.improvements),
        },
        "entries": [_entry_to_dict(e) for e in report.entries],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
