# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Version-coordinate extraction + known-vuln findings (Wave 3 Feature V).

Extends the single pinned-runner OSV lookup (``checks.pinning``) to *every*
package coordinate a server's launch command carries — a second pinned dep on an
``npx``/``uvx`` line, a ``pip``-pinned requirement behind a ``python -m`` module,
and (opt-in, under ``--inspect-process-env``) those same coordinates read from a
running agent process's cmdline.

Everything here is **pure and offline**: extraction never opens a socket. The OSV
lookup that consumes these coordinates stays behind the ``--online`` gate in the
engine, so a default scan neither imports the egress module nor emits a
``VULN-KNOWN`` finding.
"""

from __future__ import annotations

import re

from ..domain import Dimension, Finding, Location, Severity
from .pinning import (
    _NPM_RUNNERS,
    _PYPI_RUNNERS,
    PackageSpec,
    coord_from_arg,
    package_args,
)

# ``python`` / ``python3`` / ``python3.11`` launch a PyPI-ecosystem interpreter;
# a coordinate is only produced when an explicit ``name==version`` dep is present
# on the line (a bare ``python -m x`` yields nothing — the interpreter version
# itself is out of scope, per spec).
_PY_INTERPRETER = re.compile(r"^python(?:\d+(?:\.\d+)?)?$")


def _ecosystem_for(runner: str) -> str | None:
    """Map a launcher basename to its package ecosystem (or ``None``)."""
    if runner in _NPM_RUNNERS:
        return "npm"
    if runner in _PYPI_RUNNERS or _PY_INTERPRETER.match(runner):
        return "PyPI"
    return None


def extract_version_coords(command: str | None, args: tuple[str, ...]) -> list[PackageSpec]:
    """Every distinct ``(ecosystem, name, version)`` coordinate in a launch line.

    Unlike :func:`checks.pinning.parse_package_spec` (which returns only the first
    runner spec), this scans *all* non-flag args for pinned coordinates in the
    ecosystem implied by the launcher — so ``npx -p left-pad@1.0.0 cli@2.0.0`` and
    ``uvx --with extra==1.0 tool==2.0`` each yield two coordinates. Order-stable
    and de-duplicated. Returns ``[]`` for a launcher with no known ecosystem
    (e.g. ``node server.js``), so nothing is ever sent online for it.
    """
    runner = (command or "").rsplit("/", 1)[-1]
    ecosystem = _ecosystem_for(runner)
    if ecosystem is None:
        return []
    coords: list[PackageSpec] = []
    seen: set[tuple[str, str, str]] = set()
    for arg in package_args(args):
        spec = coord_from_arg(arg, ecosystem)
        if spec is None:
            continue
        key = (spec.ecosystem, spec.name, spec.version)
        if key in seen:
            continue
        seen.add(key)
        coords.append(spec)
    return coords


def extract_version_coords_from_cmdline(cmdline: str) -> list[PackageSpec]:
    """Extract coordinates from a raw process cmdline string (pure).

    The cmdline is split on whitespace into ``command`` + ``args`` and handed to
    :func:`extract_version_coords`. Used only on the opt-in
    ``--inspect-process-env`` path, over cmdlines already enumerated by
    ``discovery.process_env`` — no new process introspection happens here.
    """
    parts = cmdline.split()
    if not parts:
        return []
    command, *args = parts
    return extract_version_coords(command, tuple(args))


def vuln_known_finding(
    subject: str,
    coord: PackageSpec,
    vuln_ids: tuple[str, ...],
    location_path: str,
    *,
    critical: bool = False,
) -> Finding:
    """Build a ``VULN-KNOWN`` finding for a known-vulnerable launch coordinate.

    ``subject`` names what carries the coordinate (a server name or a running
    process) for the title; ``location_path`` is the config path or process URI.
    """
    ids = ", ".join(vuln_ids[:5])
    return Finding(
        id="VULN-KNOWN",
        dimension=Dimension.PINNING,
        severity=Severity.CRITICAL if critical else Severity.HIGH,
        title=(
            f"{subject} launches {coord.name}@{coord.version} ({coord.ecosystem}), "
            f"which has known advisories ({ids})"
        ),
        location=Location(path=location_path),
        remediation=(f"Upgrade {coord.name} past the version with the listed advisories."),
        rationale=(
            "A known-vulnerable package in the launch command exposes the host to "
            "documented exploits, even when the runner itself is pinned."
        ),
    )
