# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Exposure check: bind-address reachability (ticket T-202).

Pure transform from an observed socket bind address to a finding. The finding
names the *reachability tier* of the bind so the reader sees the blast radius:
a private-LAN bind (reachable by other hosts on the same network) is a different
story from a wildcard/public bind (reachable from any network).
"""

from __future__ import annotations

from ..discovery.sockets import ListeningSocket, ReachTier, classify_exposure, classify_reachability
from ..domain import Dimension, Finding, Location, Severity

# Per-tier phrasing for the finding title/rationale. Loopback never reaches here
# (it produces no finding), so it is intentionally absent from this map.
_TIER_PHRASE: dict[ReachTier, tuple[str, str]] = {
    ReachTier.PRIVATE_LAN: (
        "reachable on the local network",
        "private-LAN bind",
    ),
    ReachTier.PUBLIC_ROUTABLE: (
        "reachable from any network",
        "public-routable bind",
    ),
    ReachTier.WILDCARD: (
        "reachable from any network",
        "wildcard bind",
    ),
}


def check_socket_exposure(sock: ListeningSocket) -> list[Finding]:
    """Return an exposure finding if the socket binds beyond loopback."""
    severity = classify_exposure(sock.ip)
    if severity is None:
        return []
    tier = classify_reachability(sock.ip)
    reach_phrase, bind_phrase = _TIER_PHRASE[tier]
    where = f"{sock.ip}:{sock.port}"
    return [
        Finding(
            id="EXPOSE-BIND",
            dimension=Dimension.EXPOSURE,
            severity=severity,
            title=f"MCP server {reach_phrase} ({bind_phrase} {where})",
            location=Location(path=where),
            remediation=(
                "Bind the server to 127.0.0.1 (loopback) instead of "
                f"{sock.ip}. Only expose it on a network interface behind "
                "authentication if remote access is genuinely required."
            ),
            rationale=(
                f"A {bind_phrase} makes the server — and its tools — {reach_phrase}, "
                "often without authentication."
            ),
        )
    ]


__all__ = ["Severity", "check_socket_exposure"]
