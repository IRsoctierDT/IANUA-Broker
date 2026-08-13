# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Agent Trust Broker (ATB) posture check — assessment-only (governance tier).

Grades whether privileged agent-tool access is fronted by an Agent Trust Broker
and whether that broker is sound. Implements the contract in
``docs/proposals/ATB_POSTURE_CHECK.md``: mcpscan OWNS the contract and reads a
documented on-disk shape (the ``broker.json`` manifest) — it never depends on
ATB runtime code, never writes, and never enforces (ADR-17).

Pure over its inputs: the engine performs the ``io_safe`` read, this module
grades already-parsed facts, and hostile input degrades to a finding, never a
crash. Every finding rides ``Dimension.TOOL_SCOPE`` (broker governance is
tool-access control) — no new dimension, no schema bump. "Privileged" reuses the
scanner's own tool-scope predicates (:func:`is_dangerous_tool` /
:func:`has_broad_wildcard` over ``autoApprove``), so the governance view never
diverges from what ``scan``/``trust`` already flag. The manifest carries no
secrets; only these non-secret posture fields are read.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

from ..adapters.base import ServerDecl
from ..domain import Dimension, Finding, Location, Severity
from .tool_scope import has_broad_wildcard, is_dangerous_tool

# Configurable manifest postures. A missing or unknown value normalizes to the
# WORSE posture at parse time, so a manifest can never grade better than it
# verifiably is (fail-closed).
_ALLOWLIST_GOOD = "least_privilege"
_ALLOWLIST_BAD = "wildcard"
_MANIFESTS_GOOD = "signed"
_MANIFESTS_BAD = "unverified"
_AUDIT_GOOD = "enabled"
_AUDIT_BAD = "off"

# Interception wrapper: a server whose launch command (or, when that command is a
# runner, its first arg) has a basename that is or starts with this token is
# mediated at the transport by the broker's policy-enforcement point (PEP), so
# its privileged tools run behind the broker even without a manifest entry.
_WRAPPER_PREFIX = "ianua-atb"

# Launchers that run their first argument as the real program, so the wrapper may
# sit in ``args[0]`` rather than in ``command`` itself.
_RUNNERS = frozenset(
    {"npx", "pnpx", "bunx", "uvx", "uv", "pipx", "node", "python", "python3", "sh", "bash", "env"}
)


@dataclass(frozen=True)
class BrokerManifest:
    """The non-secret posture fields of a parsed ATB broker manifest.

    ``fronts`` holds ``location#name`` subject ids (the same identity the trust
    engine uses). The three posture fields are always one of their known-good or
    known-bad values — :func:`parse_broker_manifest` normalizes anything else to
    the worse posture, so the grader compares against exact strings.
    """

    schema_version: str
    fronts: tuple[str, ...]
    allowlist: str
    tool_manifests: str
    audit_log: str


@dataclass(frozen=True)
class BrokerParseError:
    """A ``broker.json`` that is present but malformed/unreadable."""

    message: str


def _normalize(value: object, good: str, bad: str) -> str:
    """Keep a known-good posture value; map anything else to the worse posture.

    Implements "unknown enum values tolerated but graded as the worse posture":
    a missing or unrecognized field can never make the broker look better than it
    verifiably is.
    """
    return good if value == good else bad


def parse_broker_manifest(raw: str) -> BrokerManifest | BrokerParseError:
    """Parse a broker manifest fail-closed. Never raises.

    Malformed JSON or a non-object top level degrades to a
    :class:`BrokerParseError` (→ ``BROKER-PARSE-ERROR``). A well-formed object
    with missing or unknown posture values parses successfully, but each such
    value is normalized to the worse posture so the grader treats an
    unverifiable broker as the more dangerous one.
    """
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return BrokerParseError("broker.json is not valid JSON")
    except RecursionError:
        # Deeply-nested JSON (under the io_safe size cap) overflows the decoder's
        # recursion; that is hostile input, not a crash. RecursionError is a
        # RuntimeError, not a ValueError, so it needs its own guard.
        return BrokerParseError("broker.json nesting is too deep to parse")
    if not isinstance(data, dict):
        return BrokerParseError("broker.json is not a JSON object")
    fronts_raw = data.get("fronts")
    fronts = tuple(str(item) for item in fronts_raw) if isinstance(fronts_raw, list) else ()
    version = data.get("schema_version")
    return BrokerManifest(
        schema_version=str(version) if version is not None else "",
        fronts=fronts,
        allowlist=_normalize(data.get("allowlist"), _ALLOWLIST_GOOD, _ALLOWLIST_BAD),
        tool_manifests=_normalize(data.get("tool_manifests"), _MANIFESTS_GOOD, _MANIFESTS_BAD),
        audit_log=_normalize(data.get("audit_log"), _AUDIT_GOOD, _AUDIT_BAD),
    )


def _basename(token: str) -> str:
    """Basename of a launch token, separator-agnostic (POSIX and Windows)."""
    return token.replace("\\", "/").rsplit("/", 1)[-1]


def routes_through_broker(server: ServerDecl) -> bool:
    """True if the server's transport is mediated by the ATB interception wrapper.

    A privileged server behind the wrapper runs its tools through the broker's
    policy-enforcement point even without a manifest ``fronts`` entry, so it is
    not "unbrokered". The wrapper is recognized by a launch basename that is or
    starts with ``ianua-atb`` — either as the command itself, or (when the
    command is a known runner/launcher) as the runner's first argument.
    """
    command = server.command or ""
    if _basename(command).startswith(_WRAPPER_PREFIX):
        return True
    if _basename(command) in _RUNNERS and server.args:
        return _basename(server.args[0]).startswith(_WRAPPER_PREFIX)
    return False


def is_privileged(server: ServerDecl) -> bool:
    """True if the server holds a dangerous or wildcard auto-approve grant.

    Reuses the scanner's own tool-scope predicates so the governance view of
    "privileged" is exactly what ``scan``/``trust`` already flag — the two can
    never diverge.
    """
    return any(
        is_dangerous_tool(entry) or has_broad_wildcard(entry) for entry in server.auto_approve
    )


def _canonical_subject(value: str, home: str | None) -> str:
    """Normalize a subject id / front entry for comparison.

    Separators are made agnostic and a leading ``~`` is expanded to ``home`` (the
    documented manifest example writes ``~/.mcp.json#shell`` while the trust
    engine discovers absolute ``location#name`` ids, so both must canonicalize to
    the same form for a correct match).
    """
    normalized = value.replace("\\", "/")
    if home and (normalized == "~" or normalized.startswith("~/")):
        normalized = home.replace("\\", "/").rstrip("/") + normalized[1:]
    return normalized


def _subject_matches_front(subject: str, front: str, home: str | None) -> bool:
    """Whether a discovered subject id is named by a manifest ``fronts`` entry.

    Both sides are ``location#name`` subject ids (the identity the trust engine
    uses). Compared for exact equality after canonicalization (separators and a
    leading ``~``): the contract (ATB_POSTURE_CHECK.md §2) is that ``fronts``
    carries exactly these subject ids, so a confident match is used rather than a
    fuzzy near-miss that could mark a server "fronted" and hide a real
    ``BROKER-ABSENT``.
    """
    return _canonical_subject(subject, home) == _canonical_subject(front, home)


def _absent_finding(subject_id: str, name: str) -> Finding:
    return Finding(
        id="BROKER-ABSENT",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title=f"Privileged server {name!r} is not fronted by an Agent Trust Broker",
        location=Location(path=subject_id),
        remediation=(
            "Front this server with an Agent Trust Broker (add its subject id to "
            "the broker manifest's 'fronts', or route it through the ianua-atb "
            "interception wrapper), or remove the dangerous/wildcard auto-approve "
            "grant that makes it privileged."
        ),
        rationale=(
            "A privileged agent tool with no broker in front of it has no "
            "reference monitor: its consequential actions run with no policy "
            "check and no human-in-the-loop gate."
        ),
    )


def _unverified_finding(manifest_path: str) -> Finding:
    return Finding(
        id="BROKER-MANIFEST-UNVERIFIED",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title="Broker fronts privileged tools with unverified tool manifests",
        location=Location(path=manifest_path),
        remediation=(
            "Configure the broker to require signed tool manifests so tool "
            "metadata is signature-checked before it reaches the agent."
        ),
        rationale=(
            "Unsigned tool manifests reopen tool-description poisoning: an "
            "attacker who alters a tool's metadata can steer the agent, and the "
            "broker will not detect the tampering."
        ),
    )


def _no_audit_finding(manifest_path: str) -> Finding:
    return Finding(
        id="BROKER-NO-AUDIT",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.MEDIUM,
        title="Broker audit log is disabled",
        location=Location(path=manifest_path),
        remediation=(
            "Enable the broker's audit log so consequential actions leave a "
            "tamper-evident oversight trail."
        ),
        rationale=(
            "With the audit log off, consequential agent actions leave no trail "
            "to detect or investigate misuse after the fact."
        ),
    )


def _permissive_finding(manifest_path: str) -> Finding:
    return Finding(
        id="BROKER-ALLOWLIST-PERMISSIVE",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.MEDIUM,
        title="Broker allowlist is wildcard, not least-privilege",
        location=Location(path=manifest_path),
        remediation=(
            "Replace the broker's wildcard allowlist with a least-privilege, explicit allowlist."
        ),
        rationale=(
            "A wildcard allowlist lets the brokered agent reach more tools than "
            "it needs, so the broker is present but not enforcing least privilege."
        ),
    )


def _parse_error_finding(manifest_path: str) -> Finding:
    return Finding(
        id="BROKER-PARSE-ERROR",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.LOW,
        title="Broker manifest is present but could not be parsed",
        location=Location(path=manifest_path),
        remediation=(
            "Fix the broker.json so its posture can be assessed (it must be a "
            "JSON object with the documented posture fields)."
        ),
        rationale=(
            "A malformed broker manifest cannot be assessed, so the broker's "
            "posture is unknown and privileged servers are treated as unbrokered."
        ),
    )


def check_broker_posture(
    subjects: Sequence[tuple[str, ServerDecl]],
    manifest_or_error: BrokerManifest | BrokerParseError | None,
    present: bool,
    *,
    manifest_path: str = "broker.json",
    home: str | None = None,
) -> list[Finding]:
    """Grade broker posture over the discovered declared servers. Pure and total.

    Args:
        subjects: ``(subject_id, decl)`` for every discovered *declared* server
            (config servers, not sockets). ``subject_id`` is the trust engine's
            ``location#name`` identity; ``decl`` supplies the privilege and
            interception-wrapper predicates.
        manifest_or_error: the parsed manifest, a parse error, or ``None`` when no
            manifest file is present.
        present: whether a ``broker.json`` file exists at all. ``False`` means no
            manifest — every privileged, non-intercepted server is
            ``BROKER-ABSENT`` and no manifest-quality finding is emitted.
        manifest_path: the manifest's path, used as the location for the
            manifest-quality and parse-error findings.

    Returns:
        Findings under ``Dimension.TOOL_SCOPE``. The fully-brokered, sound case
        (every privileged server fronted or intercepted; least-privilege
        allowlist; signed manifests; audit log enabled) yields ``[]`` — the
        positive case grades clean, which is the point of a governance tier.
    """
    manifest = manifest_or_error if isinstance(manifest_or_error, BrokerManifest) else None
    fronts = manifest.fronts if manifest is not None else ()
    findings: list[Finding] = []

    # A malformed manifest verifies nothing: it degrades to a LOW finding and is
    # treated as fronting nothing, so privileged servers below still surface as
    # BROKER-ABSENT (the conservative governance direction — never hide a gap).
    if present and isinstance(manifest_or_error, BrokerParseError):
        findings.append(_parse_error_finding(manifest_path))

    # BROKER-ABSENT: a privileged server that no manifest fronts and that does not
    # route through the interception wrapper has no reference monitor.
    fronted_privileged = False
    for subject_id, decl in subjects:
        if not is_privileged(decl):
            continue
        if any(_subject_matches_front(subject_id, front, home) for front in fronts):
            fronted_privileged = True
            continue
        if routes_through_broker(decl):
            continue
        findings.append(_absent_finding(subject_id, decl.name))

    # Manifest-quality findings fire only for a well-formed manifest.
    if manifest is not None:
        if fronted_privileged and manifest.tool_manifests == _MANIFESTS_BAD:
            findings.append(_unverified_finding(manifest_path))
        if manifest.audit_log == _AUDIT_BAD:
            findings.append(_no_audit_finding(manifest_path))
        if manifest.allowlist == _ALLOWLIST_BAD:
            findings.append(_permissive_finding(manifest_path))

    return findings
