# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Exposure check: bind-address reachability with explicit service identity.

An observed listener is not, by itself, an MCP server. This module keeps those
facts separate:

* the socket bind determines the potential exposure tier;
* caller-supplied identity evidence determines whether MCP-specific wording and
  the EXPOSE-BIND finding are justified.

Unknown and explicitly non-MCP listeners remain visible as informational
LISTENER-OBSERVED findings. Only a VERIFIED_MCP listener can produce the
severity-bearing MCP exposure finding.
"""

from __future__ import annotations

from enum import Enum

from ..discovery.sockets import ListeningSocket, ReachTier, classify_exposure, classify_reachability
from ..domain import Dimension, Finding, Location, Severity


class ListenerIdentity(Enum):
    """What the caller can actually establish about the listening service."""

    UNKNOWN = "unknown"
    NON_MCP = "non_mcp"
    VERIFIED_MCP = "verified_mcp"


_TIER_LABEL: dict[ReachTier, str] = {
    ReachTier.PRIVATE_LAN: "private-LAN bind",
    ReachTier.PUBLIC_ROUTABLE: "public-routable bind",
    ReachTier.WILDCARD: "wildcard bind",
}


def _attribution(sock: ListeningSocket) -> str:
    parts: list[str] = []
    if sock.proc_name:
        parts.append(f"process {sock.proc_name!r}")
    if sock.pid is not None:
        parts.append(f"pid {sock.pid}")
    return ", ".join(parts) if parts else "process attribution unavailable"


def _observation(
    sock: ListeningSocket,
    *,
    identity: ListenerIdentity,
    identity_evidence: str | None,
) -> list[Finding]:
    tier = classify_reachability(sock.ip)
    if tier is ReachTier.LOOPBACK:
        return []

    where = f"{sock.ip}:{sock.port}"
    bind_phrase = _TIER_LABEL[tier]
    if identity is ListenerIdentity.NON_MCP:
        identity_phrase = "non-MCP listener"
        rationale_prefix = "Available identity evidence indicates this listener is not an MCP service."
    else:
        identity_phrase = "unverified listener"
        rationale_prefix = "No MCP identity or protocol evidence is available for this listener."

    evidence = f" Identity evidence: {identity_evidence}." if identity_evidence else ""
    return [
        Finding(
            id="LISTENER-OBSERVED",
            dimension=Dimension.EXPOSURE,
            severity=Severity.INFO,
            title=f"{identity_phrase.capitalize()} observed ({bind_phrase} {where})",
            location=Location(path=where),
            remediation=(
                "Review the owning process and intended bind. If this service should be local-only, "
                "bind it to loopback or restrict it with host/network policy."
            ),
            rationale=(
                f"{rationale_prefix} Socket attribution: {_attribution(sock)}.{evidence} "
                "The bind address alone does not establish MCP identity, Internet reachability, "
                "or missing authentication."
            ),
        )
    ]


def check_socket_exposure(
    sock: ListeningSocket,
    *,
    identity: ListenerIdentity = ListenerIdentity.UNKNOWN,
    identity_evidence: str | None = None,
) -> list[Finding]:
    """Classify one observed listener without converting discovery into identity.

    Loopback listeners produce no exposure finding. Non-loopback listeners always
    remain visible. Unknown/non-MCP listeners are informational observations;
    verified MCP listeners receive the normal reach-tier severity.

    identity_evidence must be secret-free attribution or protocol evidence
    suitable for reports (for example: GET /mcp returned HTTP 405).
    """
    severity = classify_exposure(sock.ip)
    if severity is None:
        return []

    if identity is not ListenerIdentity.VERIFIED_MCP:
        return _observation(sock, identity=identity, identity_evidence=identity_evidence)

    tier = classify_reachability(sock.ip)
    bind_phrase = _TIER_LABEL[tier]
    where = f"{sock.ip}:{sock.port}"
    evidence = f" Identity evidence: {identity_evidence}." if identity_evidence else ""
    return [
        Finding(
            id="EXPOSE-BIND",
            dimension=Dimension.EXPOSURE,
            severity=severity,
            title=f"Verified MCP server uses {bind_phrase} ({where})",
            location=Location(path=where),
            remediation=(
                "Bind the MCP server to loopback when remote access is unnecessary. "
                "If remote access is required, restrict network reach and require authentication."
            ),
            rationale=(
                f"The verified MCP service is bound beyond loopback via a {bind_phrase}. "
                "That expands the socket-level exposure surface; actual external reachability "
                f"still depends on routing and firewall policy.{evidence}"
            ),
        )
    ]


__all__ = ["ListenerIdentity", "Severity", "check_socket_exposure"]
