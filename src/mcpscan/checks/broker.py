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

v1.6+: good postures and non-empty ``fronts`` require an ``evidence`` block
binding claims to an ATB audit-chain tip id + tip hash (honor-system enums
alone cannot grade clean). Wrapper detection requires a path-qualified
``ianua-atb`` binary (not a bare spoofable basename).
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..adapters.base import ServerDecl
from ..domain import Dimension, Finding, Location, Severity
from .tool_scope import has_broad_wildcard, is_dangerous_tool

_ALLOWLIST_GOOD = "least_privilege"
_ALLOWLIST_BAD = "wildcard"
_MANIFESTS_GOOD = "signed"
_MANIFESTS_BAD = "unverified"
_AUDIT_GOOD = "enabled"
_AUDIT_BAD = "off"

# Exact wrapper basenames (optional -pep/-gateway suffix, optional .exe).
_WRAPPER_BASENAME = re.compile(r"^ianua-atb(-[a-z0-9._]+)?(\.exe)?$", re.IGNORECASE)

_RUNNERS = frozenset(
    {"npx", "pnpx", "bunx", "uvx", "uv", "pipx", "node", "python", "python3", "sh", "bash", "env"}
)

_TIP_HASH = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class BrokerEvidence:
    """Cryptographic tip binding for claimed broker posture (non-secret)."""

    expect_tip: str
    expect_tip_hash: str
    chain_path: str = ""


@dataclass(frozen=True)
class BrokerManifest:
    """The non-secret posture fields of a parsed ATB broker manifest."""

    schema_version: str
    fronts: tuple[str, ...]
    allowlist: str
    tool_manifests: str
    audit_log: str
    evidence: BrokerEvidence | None = None


@dataclass(frozen=True)
class BrokerParseError:
    """A ``broker.json`` that is present but malformed/unreadable."""

    message: str


def _normalize(value: object, good: str, bad: str) -> str:
    return good if value == good else bad


def _parse_evidence(raw: object) -> BrokerEvidence | None:
    if not isinstance(raw, dict):
        return None
    tip = raw.get("expect_tip")
    tip_hash = raw.get("expect_tip_hash")
    if not isinstance(tip, str) or not tip or "\x00" in tip:
        return None
    if not isinstance(tip_hash, str) or not _TIP_HASH.fullmatch(tip_hash.lower()):
        return None
    chain = raw.get("chain_path")
    chain_path = str(chain) if isinstance(chain, str) else ""
    if "\x00" in chain_path:
        chain_path = ""
    return BrokerEvidence(
        expect_tip=tip,
        expect_tip_hash=tip_hash.lower(),
        chain_path=chain_path,
    )


def parse_broker_manifest(raw: str) -> BrokerManifest | BrokerParseError:
    """Parse a broker manifest fail-closed. Never raises."""
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return BrokerParseError("broker.json is not valid JSON")
    except RecursionError:
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
        evidence=_parse_evidence(data.get("evidence")),
    )


def _basename(token: str) -> str:
    return token.replace("\\", "/").rsplit("/", 1)[-1]


def _is_path_qualified(token: str) -> bool:
    """True when the token includes a directory separator (spoof-resistant)."""
    return "/" in token or "\\" in token


def _is_wrapper_token(token: str) -> bool:
    """Path-qualified basename matching the closed ianua-atb wrapper set."""
    if not token or not _is_path_qualified(token):
        return False
    return _WRAPPER_BASENAME.fullmatch(_basename(token)) is not None


def routes_through_broker(server: ServerDecl) -> bool:
    """True if transport is mediated by a path-qualified ianua-atb wrapper.

    Bare basenames (``ianua-atb-pep`` with no path) are rejected — a hostile
    config can place any executable on PATH under that name. The wrapper must
    appear as an absolute or relative path in ``command``, or as a
    path-qualified first argument to a known runner.
    """
    command = server.command or ""
    if _is_wrapper_token(command):
        return True
    if _basename(command) in _RUNNERS and server.args:
        return _is_wrapper_token(server.args[0])
    return False


def is_privileged(server: ServerDecl) -> bool:
    return any(
        is_dangerous_tool(entry) or has_broad_wildcard(entry) for entry in server.auto_approve
    )


def _canonical_subject(value: str, home: str | None) -> str:
    normalized = value.replace("\\", "/")
    if home and (normalized == "~" or normalized.startswith("~/")):
        normalized = home.replace("\\", "/").rstrip("/") + normalized[1:]
    return normalized


def _subject_matches_front(subject: str, front: str, home: str | None) -> bool:
    return _canonical_subject(subject, home) == _canonical_subject(front, home)


def claims_governance(manifest: BrokerManifest) -> bool:
    """True when the manifest asserts fronting or any known-good posture."""
    if manifest.fronts:
        return True
    return (
        manifest.allowlist == _ALLOWLIST_GOOD
        or manifest.tool_manifests == _MANIFESTS_GOOD
        or manifest.audit_log == _AUDIT_GOOD
    )


def verify_chain_tip(chain_text: str, evidence: BrokerEvidence) -> str | None:
    """Return None if the JSONL chain tip matches evidence; else a closed reason.

    Expects ATB-style JSONL records with ``decision_id`` and ``record_hash``.
    """
    lines = [ln for ln in chain_text.splitlines() if ln.strip()]
    if not lines:
        return "empty_chain"
    try:
        body = json.loads(lines[-1])
    except (ValueError, json.JSONDecodeError, RecursionError):
        return "tip_unparseable"
    if not isinstance(body, dict):
        return "tip_not_object"
    tip_id = body.get("decision_id")
    tip_hash = body.get("record_hash")
    if tip_id != evidence.expect_tip:
        return "tip_id_mismatch"
    if not isinstance(tip_hash, str) or tip_hash.lower() != evidence.expect_tip_hash:
        return "tip_hash_mismatch"
    return None


def _absent_finding(subject_id: str, name: str) -> Finding:
    return Finding(
        id="BROKER-ABSENT",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title=f"Privileged server {name!r} is not fronted by an Agent Trust Broker",
        location=Location(path=subject_id),
        remediation=(
            "Front this server with an Agent Trust Broker (add its subject id to "
            "the broker manifest's 'fronts', or route it through a path-qualified "
            "ianua-atb interception wrapper), or remove the dangerous/wildcard "
            "auto-approve grant that makes it privileged."
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


def _evidence_missing_finding(manifest_path: str) -> Finding:
    return Finding(
        id="BROKER-EVIDENCE-MISSING",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title="Broker posture claims lack audit-chain tip evidence",
        location=Location(path=manifest_path),
        remediation=(
            "Add an evidence block with expect_tip and expect_tip_hash (64-hex "
            "record hash of the ATB audit tip). Prefer chain_path so mcpscan can "
            "verify the tip against the local chain."
        ),
        rationale=(
            "Allowlist/manifest/audit enums are self-attested. Without a tip "
            "binding, a hostile broker.json can claim a sound broker that does "
            "not exist."
        ),
    )


def _evidence_mismatch_finding(manifest_path: str, reason: str) -> Finding:
    return Finding(
        id="BROKER-EVIDENCE-MISMATCH",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title="Broker audit-chain tip does not match declared evidence",
        location=Location(path=manifest_path),
        remediation=(
            f"Refresh broker.json evidence from the live ATB chain tip (verifier reason: {reason})."
        ),
        rationale=(
            "The declared tip id/hash does not match the readable audit chain, "
            "so posture claims are not bound to running evidence."
        ),
    )


def check_broker_posture(
    subjects: Sequence[tuple[str, ServerDecl]],
    manifest_or_error: BrokerManifest | BrokerParseError | None,
    present: bool,
    *,
    manifest_path: str = "broker.json",
    home: str | None = None,
    chain_verify_reason: str | None = None,
) -> list[Finding]:
    """Grade broker posture over discovered declared servers. Pure and total.

    ``chain_verify_reason`` is set by the engine when tip verification ran and
    failed (or the chain was unreadable); ``None`` means not attempted.
    """
    manifest = manifest_or_error if isinstance(manifest_or_error, BrokerManifest) else None
    fronts = manifest.fronts if manifest is not None else ()
    findings: list[Finding] = []

    if present and isinstance(manifest_or_error, BrokerParseError):
        findings.append(_parse_error_finding(manifest_path))

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

    if manifest is not None:
        if claims_governance(manifest) and manifest.evidence is None:
            findings.append(_evidence_missing_finding(manifest_path))
        if chain_verify_reason is not None:
            findings.append(_evidence_mismatch_finding(manifest_path, chain_verify_reason))
        if fronted_privileged and manifest.tool_manifests == _MANIFESTS_BAD:
            findings.append(_unverified_finding(manifest_path))
        if manifest.audit_log == _AUDIT_BAD:
            findings.append(_no_audit_finding(manifest_path))
        if manifest.allowlist == _ALLOWLIST_BAD:
            findings.append(_permissive_finding(manifest_path))

    return findings
