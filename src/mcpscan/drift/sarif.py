# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 for drift: each regression against a baseline, with before/after.

``mcpscan diff --sarif`` turns a :class:`DriftReport` into code-scanning alerts,
so a rug-pulled tool or a newly exposed server shows up on the pull request
that changed it, not only in a CI log.

Shape:

- **One rule per drift cause** (``DRIFT-TOOL-DESC-CHANGED``,
  ``DRIFT-EXPOSURE-DRIFT``, …), so alerts group by the class of change.
- **Regressions only.** Improvements and informational changes are not alerts;
  they stay in the terminal and JSON renderers.
- **Location.** Drift has no source line, so every result is anchored on the
  committed baseline file (the thing the posture drifted *from*; GitHub needs a
  physical file to raise an alert) and names the drifted fact as a
  ``logicalLocation`` (its stable drift key).
- **Before/after.** The message lists each field that changed as
  ``field: before → after`` (``Now:`` / ``Was:`` for an added or removed
  fact), and ``properties.before`` / ``properties.after``
  carry the full fact detail. Tool detail is digests and hints only: a
  baseline never stores description text, so neither does the alert.
- **Acceptance.** An unexpired named-human acceptance is emitted as an
  ``external``/``accepted`` suppression (the alert stays in the log, marked
  accepted), mirroring the exit gate; an expired one is live again.

Untrusted text (tool and server names inside keys and summaries) passes through
:func:`mcpscan.report.inert_text`. Output is deterministic: sorted keys, stable
ordering, no timestamps.
"""

from __future__ import annotations

import hashlib
import json
import re

from .. import __version__
from ..report import RenderOptions, inert_text
from ..report.sarif import INFORMATION_URI, SARIF_SCHEMA, SARIF_VERSION, TOOL_NAME, _source_uri
from .model import ChangeType, DriftCause, DriftEntry, DriftReport

_MAX_MESSAGE_CHARS = 2000
_HEX_DIGEST = re.compile(r"^[0-9a-f]{40,128}$")

# Why each cause matters, shown as the rule's description.
_CAUSE_TEXT: dict[DriftCause, str] = {
    DriftCause.CONFIG_DRIFT: "Configuration or permission changed since the baseline",
    DriftCause.PROVENANCE_DRIFT: "Package or version provenance changed since the baseline",
    DriftCause.EXPOSURE_DRIFT: "Network exposure changed since the baseline",
    DriftCause.INSPECTION_REGRESSION: "The scanner lost visibility it had at the baseline",
    DriftCause.INVENTORY_DRIFT: "An inventoried AI/MCP asset appeared or disappeared",
    DriftCause.TOOL_IDENTITY_DRIFT: "A server's tools changed without approval",
    DriftCause.TOOL_ADDED: "A pinned server gained a tool that was never approved",
    DriftCause.TOOL_REMOVED: "A pinned tool disappeared",
    DriftCause.TOOL_DESC_CHANGED: "A pinned tool's description changed (rug-pull window)",
    DriftCause.TOOL_SCHEMA_CHANGED: "A pinned tool's input or output schema changed",
    DriftCause.TOOL_ANNOT_RELAXED: "A pinned tool's hints now claim more capability",
    DriftCause.TOOL_ANNOT_TIGHTENED: "A pinned tool's hints now claim less capability",
    DriftCause.TOOL_PIN_CHANGED: "A tool no longer matches its imported mcpseal pin",
    DriftCause.OTHER: "Posture changed since the baseline",
}

_TOOL_HELP = (
    "Review the change at its source. If it is legitimate, record a named-human "
    "acceptance for this exact tool digest in .mcpscan-accept.json, or re-baseline; "
    "if not, disable the server."
)
_DEFAULT_HELP = "Review the change; re-baseline once it is understood and intended."

# Tool drift is exactly the rug-pull window, so it alerts as an error.
_ERROR_CAUSES = frozenset(
    {
        DriftCause.TOOL_IDENTITY_DRIFT,
        DriftCause.TOOL_ADDED,
        DriftCause.TOOL_DESC_CHANGED,
        DriftCause.TOOL_SCHEMA_CHANGED,
        DriftCause.TOOL_ANNOT_RELAXED,
        DriftCause.TOOL_PIN_CHANGED,
        DriftCause.EXPOSURE_DRIFT,
    }
)


def rule_id(cause: DriftCause) -> str:
    """The SARIF rule id for a drift cause, e.g. ``DRIFT-TOOL-DESC-CHANGED``."""
    return "DRIFT-" + cause.value.upper().replace("_", "-")


def _level(cause: DriftCause) -> str:
    return "error" if cause in _ERROR_CAUSES else "warning"


def _rule(cause: DriftCause) -> dict[str, object]:
    level = _level(cause)
    is_tool = cause.value.startswith("tool_")
    return {
        "id": rule_id(cause),
        "name": rule_id(cause),
        "shortDescription": {"text": _CAUSE_TEXT[cause]},
        "fullDescription": {"text": _CAUSE_TEXT[cause]},
        "help": {"text": _TOOL_HELP if is_tool else _DEFAULT_HELP},
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": "8.0" if level == "error" else "5.0",
            "tags": ["security", "drift"],
        },
    }


def _short(value: str) -> str:
    """A digest shortened for reading (``1a2b3c4d5e6f…``); other values verbatim."""
    if _HEX_DIGEST.match(value):
        return value[:12] + "…"
    return inert_text(value)


def _changes(entry: DriftEntry) -> list[str]:
    """``field: before → after`` for every field whose value differs."""
    before, after = dict(entry.detail_before), dict(entry.detail_after)
    lines = []
    for field in sorted(set(before) | set(after)):
        old, new = before.get(field), after.get(field)
        if old == new:
            continue
        shown_old = "(absent)" if old is None else _short(old)
        shown_new = "(absent)" if new is None else _short(new)
        lines.append(f"{inert_text(field)}: {shown_old} → {shown_new}")
    return lines


def _fields(detail: tuple[tuple[str, str], ...]) -> str:
    return "; ".join(f"{inert_text(k)}={_short(v)}" for k, v in sorted(detail))


def _message(entry: DriftEntry) -> str:
    text = f"{inert_text(entry.summary)} [{entry.change.value}, {entry.cause.value}]."
    if entry.change is ChangeType.ADDED and entry.detail_after:
        text += " Now: " + _fields(entry.detail_after) + "."
    elif entry.change is ChangeType.REMOVED and entry.detail_before:
        text += " Was: " + _fields(entry.detail_before) + "."
    elif changes := _changes(entry):
        text += " Changed: " + "; ".join(changes) + "."
    if len(text) > _MAX_MESSAGE_CHARS:
        text = text[: _MAX_MESSAGE_CHARS - 1] + "…"
    return text


def _fingerprint(entry: DriftEntry) -> str:
    """Stable per alert: the same drift keeps its alert, a new change opens a new one."""
    after = json.dumps(sorted(entry.detail_after), separators=(",", ":"))
    material = f"{entry.key}\x1f{entry.cause.value}\x1f{after}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _suppression(entry: DriftEntry) -> dict[str, object] | None:
    acceptance = entry.acceptance
    if acceptance is None or acceptance.expired:
        return None
    justification = f"Accepted by {acceptance.owner} until {acceptance.expires}"
    if acceptance.reason:
        justification += f": {acceptance.reason}"
    return {"kind": "external", "status": "accepted", "justification": inert_text(justification)}


def drift_to_sarif(
    report: DriftReport,
    *,
    baseline_path: str,
    opts: RenderOptions | None = None,
    base: str | None = None,
) -> dict[str, object]:
    """Convert a DriftReport's regressions to a SARIF 2.1.0 log dict.

    Args:
        report: The drift between a baseline and the current posture.
        baseline_path: The baseline file every result is anchored on.
        opts: Display options (path privacy for a baseline outside ``base``).
        base: The repository root; a baseline under it becomes a repo-relative
            URI so GitHub can annotate it.
    """
    opts = opts or RenderOptions()
    uri = _source_uri(baseline_path, base, opts) or "."
    regressions = sorted(report.regressions, key=lambda e: (e.key, e.cause.value))
    causes = sorted({e.cause for e in regressions}, key=lambda c: c.value)
    rule_index = {cause: i for i, cause in enumerate(causes)}

    results: list[dict[str, object]] = []
    for entry in regressions:
        result: dict[str, object] = {
            "ruleId": rule_id(entry.cause),
            "ruleIndex": rule_index[entry.cause],
            "level": _level(entry.cause),
            "message": {"text": _message(entry)},
            "locations": [
                {
                    "physicalLocation": {"artifactLocation": {"uri": uri}},
                    "logicalLocations": [
                        {
                            "name": inert_text(entry.key),
                            "fullyQualifiedName": inert_text(entry.key),
                            "kind": "resource",
                        }
                    ],
                }
            ],
            "partialFingerprints": {"mcpscanDriftHash/v1": _fingerprint(entry)},
            "properties": {
                "change": entry.change.value,
                "cause": entry.cause.value,
                "kind": entry.kind.value,
                "before": dict(entry.detail_before),
                "after": dict(entry.detail_after),
            },
        }
        suppression = _suppression(entry)
        if suppression is not None:
            result["suppressions"] = [suppression]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": INFORMATION_URI,
                        "version": __version__,
                        "rules": [_rule(c) for c in causes],
                    }
                },
                "automationDetails": {"id": "mcpscan/diff/"},
                "results": results,
            }
        ],
    }


def render_sarif_drift(
    report: DriftReport,
    *,
    baseline_path: str,
    opts: RenderOptions | None = None,
    base: str | None = None,
) -> str:
    """The drift SARIF log as deterministic JSON text."""
    log = drift_to_sarif(report, baseline_path=baseline_path, opts=opts, base=base)
    return json.dumps(log, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
