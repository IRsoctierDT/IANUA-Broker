# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Listening-socket enumeration + exposure classification (T-201, T-202).

Enumeration uses psutil (the only portable way to observe a process's bind
address, which is what the ``0.0.0.0`` exposure check requires — ADR-12). The
pure classification helpers contain no I/O and are fully unit-tested; the psutil
call degrades gracefully when the OS denies introspection (FR-D1).
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..domain import Severity

_LOOPBACK_NAMES = {"localhost"}


class ReachTier(Enum):
    """How far a bind address is reachable, from least to most exposed.

    A refinement of the old binary loopback/not-loopback split: ``PRIVATE_LAN``
    (an RFC-1918 / link-local / ULA address, reachable by other hosts on the same
    network) is a materially different blast radius from ``PUBLIC_ROUTABLE`` or a
    ``WILDCARD`` bind (reachable from any network).
    """

    LOOPBACK = "loopback"
    PRIVATE_LAN = "private_lan"
    PUBLIC_ROUTABLE = "public_routable"
    WILDCARD = "wildcard"


@dataclass(frozen=True)
class ListeningSocket:
    """A socket observed in the LISTEN state."""

    ip: str
    port: int
    pid: int | None
    proc_name: str | None


@dataclass(frozen=True)
class EnumerationResult:
    """Enumerated sockets plus whether introspection was complete."""

    sockets: tuple[ListeningSocket, ...]
    inspection_incomplete: bool = False


def is_loopback(host: str) -> bool:
    """True if ``host`` is a loopback address or name."""
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_wildcard(host: str) -> bool:
    # We are detecting a wildcard bind in scanned software, never binding here.
    return host in {"0.0.0.0", "::", ""}  # nosec B104


def classify_reachability(ip: str) -> ReachTier:
    """Classify how far a bind address is reachable into a :class:`ReachTier`.

    Pure, no I/O. Loopback (address or name) is ``LOOPBACK``; a wildcard bind
    (``0.0.0.0``/``::``/empty) is ``WILDCARD``; a private, link-local, or ULA
    address is ``PRIVATE_LAN``; any other parseable (global) address is
    ``PUBLIC_ROUTABLE``. An unparseable address is treated as ``PUBLIC_ROUTABLE``
    — conservatively assuming the worst rather than ignoring it.
    """
    if is_loopback(ip):
        return ReachTier.LOOPBACK
    if _is_wildcard(ip):
        return ReachTier.WILDCARD
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ReachTier.PUBLIC_ROUTABLE  # unparseable — assume worst
    # The unspecified address has many spellings (0.0.0.0, ::, ::0, 0::0, the
    # fully-expanded all-zeros form); `is_unspecified` catches them all, where
    # the fast string check above only covers the canonical two.
    if addr.is_unspecified:
        return ReachTier.WILDCARD
    if addr.is_private or addr.is_link_local:
        return ReachTier.PRIVATE_LAN
    return ReachTier.PUBLIC_ROUTABLE


# Severity a reachability tier maps to (loopback is not a finding at all).
_TIER_SEVERITY: dict[ReachTier, Severity | None] = {
    ReachTier.LOOPBACK: None,
    ReachTier.PRIVATE_LAN: Severity.HIGH,
    ReachTier.PUBLIC_ROUTABLE: Severity.CRITICAL,
    ReachTier.WILDCARD: Severity.CRITICAL,
}


def classify_exposure(ip: str) -> Severity | None:
    """Classify a bind address's exposure severity, on top of the reach tier.

    Returns ``None`` for a loopback bind (no exposure). A private-LAN bind is
    ``HIGH`` (reachable by other hosts on the same network); a public-routable or
    wildcard bind is ``CRITICAL`` (reachable from any network). An unparseable
    address classifies as public-routable and is therefore ``CRITICAL``.
    """
    return _TIER_SEVERITY[classify_reachability(ip)]


def parse_lsof_listeners(output: str) -> tuple[ListeningSocket, ...]:
    """Parse ``lsof -Fpcn`` machine-format output into listening sockets.

    Pure (no I/O). Lines come in per-process groups: ``p<pid>``, ``c<command>``,
    then one ``n<addr>`` per socket (e.g. ``*:8199``, ``127.0.0.1:8080``,
    ``[::1]:443``). A dual-stack listener repeats the same name per address
    family, so results are deduped on (ip, port, pid).
    """
    found: list[ListeningSocket] = []
    seen: set[tuple[str, int, int | None]] = set()
    pid: int | None = None
    proc_name: str | None = None
    for line in output.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            pid = int(value) if value.isdigit() else None
            proc_name = None
        elif tag == "c":
            proc_name = value or None
        elif tag == "n":
            host, sep, port_str = value.rpartition(":")
            if not sep or not port_str.isdigit():
                continue
            host = host.strip("[]")
            if host == "*":  # lsof's wildcard-bind notation
                host = "0.0.0.0"  # nosec B104 (detecting, not binding)
            key = (host, int(port_str), pid)
            if key in seen:
                continue
            seen.add(key)
            found.append(ListeningSocket(ip=host, port=int(port_str), pid=pid, proc_name=proc_name))
    return tuple(found)


def _lsof_fallback() -> EnumerationResult | None:
    """Best-effort listener enumeration via ``lsof`` for POSIX hosts.

    On macOS, ``psutil.net_connections`` requires root; ``lsof`` can still see
    the invoking user's own processes. Returns ``None`` when lsof is missing or
    fails. Results stay ``inspection_incomplete=True`` because other users'
    listeners remain invisible without elevation.
    """
    lsof = shutil.which("lsof")
    if lsof is None:
        return None
    try:
        proc = subprocess.run(  # nosec B603 (fixed argv, no shell)
            [lsof, "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # lsof exits 1 when nothing matched; anything else is a real failure.
    if proc.returncode not in (0, 1):
        return None
    return EnumerationResult(sockets=parse_lsof_listeners(proc.stdout), inspection_incomplete=True)


def enumerate_listening() -> EnumerationResult:
    """Enumerate listening sockets via psutil, degrading on permission limits.

    Never raises: if psutil is unavailable or access is denied, falls back to
    ``lsof`` (own-user listeners only), and failing that returns whatever was
    gathered with ``inspection_incomplete=True`` (FR-D1).
    """
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is a declared dependency
        return EnumerationResult(sockets=(), inspection_incomplete=True)

    incomplete = False
    found: list[ListeningSocket] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError):
        fallback = _lsof_fallback()
        if fallback is not None:
            return fallback
        return EnumerationResult(sockets=(), inspection_incomplete=True)

    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        # psutil types laddr as `addr | tuple[()]`; the guard above proves it is
        # a populated addr here.
        laddr: Any = conn.laddr
        proc_name: str | None = None
        if conn.pid is not None:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.Error, OSError):
                incomplete = True
        found.append(
            ListeningSocket(
                ip=laddr.ip,
                port=laddr.port,
                pid=conn.pid,
                proc_name=proc_name,
            )
        )

    return EnumerationResult(sockets=tuple(found), inspection_incomplete=incomplete)
