# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Acceptance ledger: named-human, expiring risk acceptances (Wave 1 Feature D).

An operator can accept a *tool-scope* finding by recording who owns the risk
and until when in ``<root>/.mcpscan-accept.json``. An unexpired acceptance
stops the finding from failing the CLI exit gate but changes nothing else:
**accepted findings still lower the grade; they only stop failing the gate** —
posture is what it is, acceptance relaxes CI failure, not the measurement.

Guardrails (the named-human-owner rule, applied narrowly):

- Only findings with dimension ``TOOL_SCOPE`` are acceptable. A ledger entry
  that matches any other finding is refused with a warning — credential,
  exposure, and pinning findings cannot be risk-accepted.
- **Tool-drift acceptances** (R-LIVE-TOOL-DRIFT) waive one specific per-tool
  drift in ``mcpscan diff``: an entry with ``server``, ``tool`` and the new
  tool ``digest`` (instead of ``finding``) accepts exactly that version of that
  tool. Any further change produces a new digest and gates again.
- Every entry must name a human ``owner`` and an ``expires`` date. An expired
  acceptance is **not** applied: the finding gates again, and renderers
  annotate the lapse loudly instead of silently un-suppressing it.

Determinism and I/O stance: parsing and application are pure — "today" is a
parameter supplied by the CLI (no ``datetime.now()`` here), so identical
inputs always yield identical output. The only I/O is :func:`load_ledgers`,
which reads each ledger through ``io_safe.safe_read_text`` (size-capped,
symlink-safe) and degrades every failure to a warning: a malformed ledger
never crashes a scan. Nothing in this module writes a file or prints.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path

from .domain import Acceptance, Dimension, Report
from .drift.model import Direction, DriftReport, FactKind
from .io_safe import SafeReadError, safe_read_text

LEDGER_FILENAME = ".mcpscan-accept.json"

# A ledger is small, operator-authored JSON; cap it well below io_safe's 5 MB.
_MAX_LEDGER_BYTES = 1 * 1024 * 1024  # 1 MB

_REQUIRED_KEYS = ("finding", "server", "owner", "expires")
_TOOL_REQUIRED_KEYS = ("server", "tool", "digest", "owner", "expires")
_OPTIONAL_KEYS = ("accepted", "reason")


@dataclass(frozen=True)
class LedgerEntry:
    """One parsed, validated acceptance row from a ledger file."""

    finding: str
    server: str
    owner: str
    accepted: str
    expires: str
    reason: str


@dataclass(frozen=True)
class ToolDriftAcceptance:
    """One acceptance of a specific version (``digest``) of one live tool."""

    server: str
    tool: str
    digest: str
    owner: str
    accepted: str
    expires: str
    reason: str


@dataclass(frozen=True)
class LedgerLoad:
    """The outcome of reading ledgers: usable entries plus operator warnings."""

    entries: tuple[LedgerEntry, ...] = ()
    warnings: tuple[str, ...] = ()
    tool_entries: tuple[ToolDriftAcceptance, ...] = ()


def _is_tool_entry(raw: object) -> bool:
    return isinstance(raw, dict) and "tool" in raw and "finding" not in raw


def _entry_problem(raw: object) -> str | None:
    """Why an acceptance row is unusable, or ``None`` when it is valid."""
    if not isinstance(raw, dict):
        return "entry is not an object"
    required = _TOOL_REQUIRED_KEYS if _is_tool_entry(raw) else _REQUIRED_KEYS
    if _is_tool_entry(raw):
        digest = raw.get("digest")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            return "'digest' must be the tool's 64-hex sha256 digest"
    for key in required:
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            return f"missing or empty {key!r} (a named human owner and an expiry are required)"
    for key in _OPTIONAL_KEYS:
        if key in raw and not isinstance(raw[key], str):
            return f"{key!r} must be a string"
    try:
        date.fromisoformat(raw["expires"])
    except ValueError:
        return f"invalid 'expires' date {raw['expires']!r} (expected YYYY-MM-DD)"
    return None


def parse_ledger(text: str, source: str) -> LedgerLoad:
    """Parse one ledger's JSON text (pure; malformed input warns, never raises).

    Expected shape: ``{"acceptances": [{"finding": ..., "server": ...,
    "owner": ..., "accepted": ..., "expires": ..., "reason": ...}, ...]}``.
    A malformed document is ignored whole; a malformed entry is skipped
    individually — in both cases with a warning naming ``source``.
    """
    try:
        data = json.loads(text)
    except ValueError:
        return LedgerLoad(
            warnings=(f"ignoring malformed acceptance ledger {source}: not valid JSON",)
        )
    except RecursionError:
        # Deeply-nested JSON overflows the decoder well under the 1 MB cap.
        # RecursionError is a RuntimeError, not a ValueError — a ledger dropped
        # in a scanned root must never crash the scan (NFR-S3).
        return LedgerLoad(
            warnings=(f"ignoring malformed acceptance ledger {source}: nesting is too deep",)
        )
    if not isinstance(data, dict) or not isinstance(data.get("acceptances"), list):
        return LedgerLoad(
            warnings=(
                f'ignoring malformed acceptance ledger {source}: expected {{"acceptances": [...]}}',
            )
        )
    entries: list[LedgerEntry] = []
    tool_entries: list[ToolDriftAcceptance] = []
    warnings: list[str] = []
    for index, raw in enumerate(data["acceptances"]):
        problem = _entry_problem(raw)
        if problem is not None:
            warnings.append(f"ignoring acceptance #{index + 1} in {source}: {problem}")
            continue
        if _is_tool_entry(raw):
            tool_entries.append(
                ToolDriftAcceptance(
                    server=raw["server"],
                    tool=raw["tool"],
                    digest=raw["digest"],
                    owner=raw["owner"],
                    accepted=raw.get("accepted", ""),
                    expires=raw["expires"],
                    reason=raw.get("reason", ""),
                )
            )
            continue
        entries.append(
            LedgerEntry(
                finding=raw["finding"],
                server=raw["server"],
                owner=raw["owner"],
                accepted=raw.get("accepted", ""),
                expires=raw["expires"],
                reason=raw.get("reason", ""),
            )
        )
    return LedgerLoad(
        entries=tuple(entries), warnings=tuple(warnings), tool_entries=tuple(tool_entries)
    )


def load_ledgers(roots: Sequence[Path]) -> LedgerLoad:
    """Read ``<root>/.mcpscan-accept.json`` from each root (missing → skipped).

    The single I/O edge of this module. Reads go through ``safe_read_text``
    (bounded at 1 MB, symlink-safe), and an unreadable or malformed ledger
    becomes a warning, never an exception — operator-authored metadata must
    not crash a scan. Entry order is root order, then file order, so the
    result is deterministic for a given filesystem state.
    """
    entries: list[LedgerEntry] = []
    tool_entries: list[ToolDriftAcceptance] = []
    warnings: list[str] = []
    for root in roots:
        path = root / LEDGER_FILENAME
        if not path.exists():
            continue
        try:
            text = safe_read_text(path, root=root, max_bytes=_MAX_LEDGER_BYTES)
        except SafeReadError as exc:
            warnings.append(f"ignoring unreadable acceptance ledger {path}: {exc}")
            continue
        loaded = parse_ledger(text, str(path))
        entries.extend(loaded.entries)
        tool_entries.extend(loaded.tool_entries)
        warnings.extend(loaded.warnings)
    return LedgerLoad(
        entries=tuple(entries), warnings=tuple(warnings), tool_entries=tuple(tool_entries)
    )


def acceptance_expired(expires: str, *, today: date) -> bool:
    """Whether an acceptance has lapsed: strictly after its ``expires`` date.

    Deterministic — ``today`` is injected by the CLI (computed once from the
    UTC wall clock). On the expiry date itself the acceptance still holds
    ("accepted **until**"); from the next day on it is expired. ``expires``
    is already validated by :func:`parse_ledger`, so parsing cannot fail here.
    """
    return today > date.fromisoformat(expires)


def _server_matches(server_id: str, entry_server: str) -> bool:
    """Exact server-id match, or the declared-server ``#<name>`` suffix form."""
    return server_id == entry_server or server_id.endswith("#" + entry_server)


def apply_acceptances(
    report: Report, entries: Sequence[LedgerEntry], *, today: date
) -> tuple[Report, tuple[str, ...]]:
    """Attach ledger acceptances to matching findings; return (report, warnings).

    Matching: ``finding.id`` equality AND the owning server's id either equals
    the entry's ``server`` or ends with ``"#" + server`` (the declared-server
    suffix). Only ``TOOL_SCOPE`` findings are acceptable — an entry matching
    any other dimension is refused with a warning (credential/exposure/pinning
    findings cannot be risk-accepted). The first matching entry wins.

    An **expired** acceptance is still attached, flagged ``expired=True``, so
    renderers can be loud about the lapse — but the exit gate treats the
    finding as unaccepted again. Grades are untouched either way: scoring
    never looks at acceptance, and the report's precomputed grades stand.

    Pure and deterministic: frozen servers/findings are rebuilt via
    :func:`dataclasses.replace`; ``today`` comes from the caller.
    """
    if not entries:
        return report, ()
    warnings: list[str] = []
    servers = []
    for server in report.servers:
        candidates = [e for e in entries if _server_matches(server.id, e.server)]
        if not candidates:
            servers.append(server)
            continue
        findings = []
        touched = False
        for finding in server.findings:
            matches = [e for e in candidates if e.finding == finding.id]
            # Prefer a currently-valid entry: an operator who appends a renewal
            # after a lapse must not be shadowed by the stale entry above it.
            entry = next(
                (e for e in matches if not acceptance_expired(e.expires, today=today)),
                matches[0] if matches else None,
            )
            if entry is None or finding.acceptance is not None:
                findings.append(finding)
                continue
            if finding.dimension is not Dimension.TOOL_SCOPE:
                warnings.append(
                    f"acceptance for {finding.id} on {server.id} ignored — "
                    "credential/exposure/pinning findings cannot be risk-accepted"
                )
                findings.append(finding)
                continue
            acceptance = Acceptance(
                owner=entry.owner,
                accepted=entry.accepted,
                expires=entry.expires,
                reason=entry.reason,
                expired=acceptance_expired(entry.expires, today=today),
            )
            findings.append(replace(finding, acceptance=acceptance))
            touched = True
        servers.append(replace(server, findings=tuple(findings)) if touched else server)
    return replace(report, servers=tuple(servers)), tuple(warnings)


def apply_tool_drift_acceptances(
    report: DriftReport, entries: Sequence[ToolDriftAcceptance], *, today: date
) -> DriftReport:
    """Waive per-tool drift regressions that a named human accepted (pure).

    An entry matches a TOOL regression when its ``server`` equals the drifted
    tool's server id, its ``tool`` equals the tool name, and its ``digest``
    equals the tool's **new** digest — so the acceptance covers exactly the
    version a human reviewed, and any later change gates again. A valid match
    turns the entry INFORMATIONAL; an expired one is attached (``expired=True``)
    but the entry stays a REGRESSION, so the lapse is loud rather than silent.
    ``today`` is injected by the CLI.
    """
    if not entries:
        return report
    updated = []
    for entry in report.entries:
        after = dict(entry.detail_after)
        if entry.kind is not FactKind.TOOL or entry.direction is not Direction.REGRESSION:
            updated.append(entry)
            continue
        server = after.get("server", "")
        tool = entry.key.removeprefix(f"tool:{server}:")
        matches = [
            e
            for e in entries
            if e.server == server and e.tool == tool and e.digest == after.get("digest")
        ]
        chosen = next(
            (e for e in matches if not acceptance_expired(e.expires, today=today)),
            matches[0] if matches else None,
        )
        if chosen is None:
            updated.append(entry)
            continue
        expired = acceptance_expired(chosen.expires, today=today)
        acceptance = Acceptance(
            owner=chosen.owner,
            accepted=chosen.accepted,
            expires=chosen.expires,
            reason=chosen.reason,
            expired=expired,
        )
        updated.append(
            replace(
                entry,
                acceptance=acceptance,
                direction=entry.direction if expired else Direction.INFORMATIONAL,
            )
        )
    return replace(report, entries=tuple(updated))
