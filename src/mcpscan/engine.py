# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Scan pipeline: discover → audit → score → assemble Report (Sprint 2 wiring).

Orchestrates the pure checks and the I/O edges into a single deterministic
``Report``. All file reads go through ``io_safe``; the only network touched here
is the loopback probe (and only when ``probe=True``). No file is ever written.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess  # nosec B404
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from .adapters.base import HostAdapter, ParsedConfig
from .adapters.claude import ClaudeAdapter
from .adapters.cline import ClineAdapter
from .adapters.continue_ import ContinueAdapter
from .adapters.cursor import CursorAdapter
from .adapters.vscode import VSCodeAdapter
from .adapters.windsurf import WindsurfAdapter
from .adapters.zed import ZedAdapter
from .checks import EnvFile, parse_env_text
from .checks.exposure import check_socket_exposure
from .checks.pinning import (
    PackageSpec,
    check_server_pinning,
    known_vuln_finding,
    parse_package_spec,
)
from .checks.secrets import (
    check_env_file_secrets,
    check_secret_at_rest,
    check_secret_reuse,
    check_server_env,
)
from .checks.tool_scope import (
    check_permissions,
    check_server_auto_approve,
)
from .discovery.sockets import EnumerationResult, enumerate_listening
from .domain import Finding, Report, Server, ServerState
from .io_safe import SafeReadError, safe_read_text
from .scoring import dimension_grades, grade_findings, worst_grade

# "1.1": findings gained the optional "acceptance" object (Wave 1 Feature D —
# named-human, expiring risk acceptances; see mcpscan.acceptance).
SCHEMA_VERSION = "1.1"

# (name, version, ecosystem) -> (vuln_ids, any_critical)
OsvFetch = Callable[[str, str, str], "tuple[tuple[str, ...], bool]"]


def _adapters() -> tuple[HostAdapter, ...]:
    """The registered host adapters (ADR-4), in discovery priority order."""
    return (
        ClaudeAdapter(),
        CursorAdapter(),
        WindsurfAdapter(),
        ClineAdapter(),
        VSCodeAdapter(),
        ZedAdapter(),
        ContinueAdapter(),
    )


def discover_host_config_files(
    *,
    roots: Sequence[Path] | None = None,
    system: str | None = None,
    env: Mapping[str, str] | None = None,
) -> list[Path]:
    """Return the existing host-config files a scan would read (user + project).

    Deduped, order-stable, host-config only (no ``.env``). Used by ``--fix`` so
    remediation targets exactly the files the scan audited.
    """
    system = system or platform.system()
    env = env if env is not None else os.environ
    roots = list(roots) if roots is not None else [Path.cwd()]
    adapters = _adapters()

    seen: list[Path] = []

    def _add(path: Path) -> None:
        if path not in seen and path.exists() and path.is_file():
            seen.append(path)

    for adapter in adapters:
        for cand in adapter.default_config_paths(system, env):
            _add(Path(str(cand)))
    for root in roots:
        for adapter in adapters:
            for path in adapter.project_config_paths(root):
                _add(path)
    return seen


def _audit_config(cfg: ParsedConfig, osv_fetch: OsvFetch | None = None) -> list[Server]:
    servers: list[Server] = []
    for decl in cfg.servers:
        findings: list[Finding] = []
        findings += check_server_env(decl, cfg.path)
        findings += check_server_auto_approve(decl, cfg.path)
        findings += check_server_pinning(decl, cfg.path)
        if osv_fetch is not None:
            findings += _enrich_pinning(decl.name, decl.command, decl.args, cfg.path, osv_fetch)
        servers.append(
            Server(
                id=f"{cfg.path}#{decl.name}",
                bind_addr=None,
                port=None,
                pid=None,
                proc_name=None,
                state=ServerState.DECLARED,
                running=False,
                findings=tuple(findings),
            )
        )

    # Config-level permission grants (not tied to one server).
    perm_findings = check_permissions(cfg.allow_permissions, cfg.path)
    if perm_findings:
        servers.append(
            Server(
                id=f"{cfg.path}#permissions",
                bind_addr=None,
                port=None,
                pid=None,
                proc_name=None,
                state=ServerState.DECLARED,
                running=False,
                findings=tuple(perm_findings),
            )
        )
    return servers


def _enrich_pinning(
    server_name: str,
    command: str | None,
    args: tuple[str, ...],
    config_path: str,
    osv_fetch: OsvFetch,
) -> list[Finding]:
    """Query OSV for a pinned package spec and emit a known-vuln finding if any."""
    spec: PackageSpec | None = parse_package_spec(command, args)
    if spec is None:
        return []
    vuln_ids, critical = osv_fetch(spec.name, spec.version, spec.ecosystem)
    if not vuln_ids:
        return []
    return [known_vuln_finding(server_name, spec, vuln_ids, config_path, critical=critical)]


def _default_osv_fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
    """Real OSV lookup. Imported lazily so egress code never loads by default."""
    from .enrichment.osv import query_osv

    vulns = query_osv(name, version, ecosystem)
    return tuple(v.id for v in vulns), any(v.critical for v in vulns)


def _audit_env_file(env_file: EnvFile) -> Server:
    findings = check_env_file_secrets(env_file) + check_secret_at_rest(env_file)
    return Server(
        id=env_file.path,
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=tuple(findings),
    )


def _server_from_socket(
    result_incomplete: bool,
    sock_ip: str,
    sock_port: int,
    pid: int | None,
    proc: str | None,
    findings: Sequence[Finding],
) -> Server:
    return Server(
        id=f"socket://{sock_ip}:{sock_port}",
        bind_addr=sock_ip,
        port=sock_port,
        pid=pid,
        proc_name=proc,
        state=ServerState.RUNNING,
        running=True,
        inspection_incomplete=result_incomplete,
        findings=tuple(findings),
    )


def _git_tracked(path: Path) -> bool | None:
    """Whether git tracks ``path``; ``None`` when unknown (no git, no repo, error).

    Read-only (``git ls-files`` never touches the index or worktree), so the
    engine's no-writes guarantee holds.
    """
    git = shutil.which("git")
    if git is None:
        return None
    try:
        proc = subprocess.run(  # nosec B603 (fixed argv, no shell)
            [git, "-C", str(path.parent), "ls-files", "--error-unmatch", "--", path.name],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:  # inside a repo, but untracked
        return False
    return None  # e.g. 128: not a git repository


def _read_config_file(path: Path) -> str | None:
    try:
        return safe_read_text(path, root=path.parent)
    except SafeReadError:
        return None


def scan(
    *,
    roots: Sequence[Path] | None = None,
    system: str | None = None,
    env: Mapping[str, str] | None = None,
    enumerate_sockets: bool = True,
    online: bool = False,
    osv_fetch: OsvFetch | None = None,
) -> Report:
    """Run a full localhost scan and return a deterministic Report.

    Args:
        roots: Project roots to scan for ``.mcp.json`` / ``.env`` (defaults to cwd).
        system: ``platform.system()`` override (for testing).
        env: Environment mapping override (for testing).
        enumerate_sockets: When False, skips psutil enumeration (used in tests).
        online: When True, enriches pinned packages with OSV advisories. The
            egress module is imported only on this path (NFR-SEC1).
        osv_fetch: Inject a fetcher (tests); defaults to the real OSV lookup when
            ``online`` is True.
    """
    system = system or platform.system()
    env = env if env is not None else os.environ
    roots = list(roots) if roots is not None else [Path.cwd()]

    fetch: OsvFetch | None = None
    if online:
        fetch = osv_fetch if osv_fetch is not None else _default_osv_fetch

    adapters = _adapters()
    servers: list[Server] = []

    # --- user-level (default) host configs ---
    for adapter in adapters:
        for cand in adapter.default_config_paths(system, env):
            path = Path(str(cand))
            raw = _read_config_file(path)
            if raw is None:
                continue
            servers.extend(_audit_config(adapter.parse(str(path), raw), fetch))

    # --- project-scoped host configs + .env ---
    for root in roots:
        for adapter in adapters:
            for path in adapter.project_config_paths(root):
                if not path.exists():
                    continue
                raw = _read_config_file(path)
                if raw is None:
                    continue
                servers.extend(_audit_config(adapter.parse(str(path), raw), fetch))
        env_path = root / ".env"
        if env_path.exists():
            raw = _read_config_file(env_path)
            if raw is not None:
                mode = stat.S_IMODE(env_path.stat().st_mode)
                env_file = parse_env_text(
                    str(env_path), raw, mode=mode, git_tracked=_git_tracked(env_path)
                )
                servers.append(_audit_env_file(env_file))

    # --- running-server discovery + exposure ---
    if enumerate_sockets:
        result: EnumerationResult = enumerate_listening()
        for sock in result.sockets:
            exposure = check_socket_exposure(sock)
            if exposure:  # only surface sockets that are actually exposed
                servers.append(
                    _server_from_socket(
                        result.inspection_incomplete,
                        sock.ip,
                        sock.port,
                        sock.pid,
                        sock.proc_name,
                        exposure,
                    )
                )

    return _assemble_report(servers, online=online)


def _assemble_report(servers: Sequence[Server], *, online: bool = False) -> Report:
    """Grade the assembled servers into a Report.

    Cross-server blast-radius findings (``CRED-REUSE``) are computed over the
    full server set and appended to each involved server *before* grading, so
    grades reflect them. Servers are frozen, so involved ones are rebuilt with
    :func:`dataclasses.replace`.
    """
    reuse = check_secret_reuse(servers)
    if reuse:
        servers = [
            replace(s, findings=s.findings + tuple(reuse[s.id])) if s.id in reuse else s
            for s in servers
        ]
    all_findings = [f for s in servers for f in s.findings]
    server_grades = [grade_findings(s.findings) for s in servers]
    return Report(
        schema_version=SCHEMA_VERSION,
        servers=tuple(servers),
        overall_grade=worst_grade(server_grades),
        dimension_grades=dimension_grades(all_findings),
        generated_with_online=online,
    )
