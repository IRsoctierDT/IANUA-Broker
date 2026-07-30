# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""OSV.dev lookups for known-vulnerable package versions (ticket T-401).

This is egress code. ``query_osv`` is the only function that opens a socket, and
it sends only the package coordinates required for the lookup. The response
parser ``parse_osv_response`` is pure and unit-tested; the HTTP call is exercised
via injection in tests, never against the live service.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

OSV_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True)
class OsvVuln:
    """A single OSV advisory affecting the queried version."""

    id: str
    critical: bool


def parse_osv_response(data: object) -> list[OsvVuln]:
    """Parse an OSV ``/v1/query`` response into advisories (pure)."""
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulns")
    if not isinstance(vulns, list):
        return []
    out: list[OsvVuln] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        vid = str(vuln.get("id", "")) or "UNKNOWN"
        out.append(OsvVuln(id=vid, critical=_is_critical(vuln)))
    return out


def _is_critical(vuln: dict[str, object]) -> bool:
    """Best-effort: treat a CVSS string containing a 9.x base or an explicit
    CRITICAL label as critical; otherwise high."""
    blob = json.dumps(vuln).upper()
    return "CRITICAL" in blob or "/AV:" in blob and "9." in blob


def query_osv(
    name: str,
    version: str,
    ecosystem: str,
    *,
    timeout: float = 5.0,
) -> list[OsvVuln]:
    """Query OSV for advisories affecting ``name@version`` in ``ecosystem``.

    Sends only the package coordinates. Returns ``[]`` on any network/parse
    error (fail safe — enrichment never breaks a scan).
    """
    body = json.dumps(
        {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    ).encode("utf-8")
    request = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # nosec B310
            payload = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError):
        return []
    return parse_osv_response(payload)
