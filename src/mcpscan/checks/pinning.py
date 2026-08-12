# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Version-pinning checks (ticket T-209).

Flags MCP servers launched from unpinned package specs (npx/uvx/pip), where a
floating version is a silent supply-chain risk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..adapters.base import ServerDecl
from ..domain import Dimension, Finding, Location, Severity

_VERSIONED = re.compile(r"@\d|@latest|==|@[~^]?\d")
_LATEST = re.compile(r"@latest\b")
_FLOATING_RUNNERS = {"npx", "uvx", "pnpx", "bunx"}

_NPM_RUNNERS = {"npx", "pnpx", "bunx"}
_PYPI_RUNNERS = {"uvx", "pipx", "pip"}


def package_args(args: tuple[str, ...]) -> list[str]:
    """The non-flag positional args (drops anything starting with ``-``)."""
    return [a for a in args if not a.startswith("-")]


@dataclass(frozen=True)
class PackageSpec:
    """A resolved, version-pinned package coordinate for OSV enrichment."""

    ecosystem: str  # "npm" or "PyPI"
    name: str
    version: str


def coord_from_arg(arg: str, ecosystem: str) -> PackageSpec | None:
    """Parse one ``name@version`` (npm) / ``name==version`` (PyPI) token (pure).

    Returns ``None`` unless the token carries a concrete version, so online
    enrichment only ever sends a fully-pinned coordinate (review F3). Shared by
    the single-spec :func:`parse_package_spec` and the multi-coord extractor in
    ``checks.versions``.
    """
    if ecosystem == "npm" and "@" in arg.lstrip("@"):
        name, _, version = arg.rpartition("@")
        if name and version and version[0].isdigit():
            return PackageSpec(ecosystem, name, version)
    elif ecosystem == "PyPI" and "==" in arg:
        name, _, version = arg.partition("==")
        if name and version:
            return PackageSpec(ecosystem, name, version)
    return None


def parse_package_spec(command: str | None, args: tuple[str, ...]) -> PackageSpec | None:
    """Extract an ecosystem/name/version from a runner command + args.

    Returns ``None`` unless a concrete version is present (so online enrichment
    only ever sends a fully-pinned coordinate — review F3). This is the single
    *runner* spec only; ``checks.versions.extract_version_coords`` finds every
    coordinate a command carries.
    """
    runner = (command or "").rsplit("/", 1)[-1]
    if runner in _NPM_RUNNERS:
        ecosystem = "npm"
    elif runner in _PYPI_RUNNERS:
        ecosystem = "PyPI"
    else:
        return None

    for arg in package_args(args):
        spec = coord_from_arg(arg, ecosystem)
        if spec is not None:
            return spec
    return None


def known_vuln_finding(
    server_name: str,
    spec: PackageSpec,
    vuln_ids: tuple[str, ...],
    config_path: str,
    *,
    critical: bool = False,
) -> Finding:
    """Build a finding for a pinned-but-known-vulnerable package (online)."""
    ids = ", ".join(vuln_ids[:5])
    return Finding(
        id="PIN-KNOWN-VULN",
        dimension=Dimension.PINNING,
        severity=Severity.CRITICAL if critical else Severity.HIGH,
        title=(
            f"Server {server_name!r} pins {spec.name}@{spec.version}, which has "
            f"known advisories ({ids})"
        ),
        location=Location(path=config_path),
        remediation=(f"Upgrade {spec.name} to a version without the listed advisories."),
        rationale="A known-vulnerable dependency exposes the host to documented exploits.",
    )


def check_server_pinning(server: ServerDecl, config_path: str) -> list[Finding]:
    """Flag an unpinned package runner command for a declared server."""
    command = (server.command or "").rsplit("/", 1)[-1]
    if command not in _FLOATING_RUNNERS:
        return []

    packages = package_args(server.args)
    if not packages:
        return []

    pinned = any(_VERSIONED.search(a) and not _LATEST.search(a) for a in packages)
    uses_latest = any(_LATEST.search(a) for a in packages)

    if pinned and not uses_latest:
        return []

    title = (
        f"Server {server.name!r} pinned to a floating tag (@latest)"
        if uses_latest
        else f"Server {server.name!r} runs an unpinned package via {command}"
    )
    return [
        Finding(
            id="PIN-UNPINNED",
            dimension=Dimension.PINNING,
            severity=Severity.MEDIUM,
            title=title,
            location=Location(path=config_path),
            remediation=(
                f"Pin the package to an exact version (e.g. {command} "
                "some-pkg@1.2.3) so the running code can't change silently."
            ),
            rationale=(
                "An unpinned/floating package fetches new code on each run — a "
                "supply-chain and reproducibility risk."
            ),
        )
    ]
