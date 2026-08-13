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

from .adapters.base import HostAdapter, ParsedConfig, ServerDecl
from .adapters.claude import ClaudeAdapter
from .adapters.cline import ClineAdapter
from .adapters.continue_ import ContinueAdapter
from .adapters.cursor import CursorAdapter
from .adapters.paths import datapack_store_path, ianua_broker_manifest_candidates
from .adapters.vscode import VSCodeAdapter
from .adapters.windsurf import WindsurfAdapter
from .adapters.zed import ZedAdapter
from .checks import EnvFile, parse_env_text
from .checks.broker import (
    BrokerManifest,
    BrokerParseError,
    check_broker_posture,
    parse_broker_manifest,
)
from .checks.exposure import check_socket_exposure
from .checks.pinning import (
    PackageSpec,
    check_server_pinning,
    known_vuln_finding,
    parse_package_spec,
)
from .checks.secrets import (
    check_env_file_secrets,
    check_process_env_secrets,
    check_secret_at_rest,
    check_secret_reuse,
    check_server_env,
)
from .checks.telemetry import check_telemetry
from .checks.token_store import check_token_store, decode_store
from .checks.tool_integrity import check_tool_integrity
from .checks.tool_scope import (
    check_permissions,
    check_server_auto_approve,
)
from .checks.versions import (
    extract_version_coords,
    extract_version_coords_from_cmdline,
    vuln_known_finding,
)
from .datapack import (
    AgentCatalog,
    SecretCatalog,
    builtin_datapack,
    compile_agent_catalog,
    compile_secret_catalog,
    load_local_datapack,
)
from .discovery.process_env import iter_agent_process_envs, looks_like_agent
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


def _audit_config(
    cfg: ParsedConfig,
    osv_fetch: OsvFetch | None = None,
    secret_catalog: SecretCatalog | None = None,
) -> list[Server]:
    # Imported lazily: the drift package pulls in inventory→collect→engine, so a
    # top-level import here would close a circular-import loop at load time.
    from .drift.snapshot import tool_identity

    servers: list[Server] = []
    for decl in cfg.servers:
        findings: list[Finding] = []
        findings += check_server_env(decl, cfg.path, catalog=secret_catalog)
        findings += check_server_auto_approve(decl, cfg.path)
        findings += check_server_pinning(decl, cfg.path)
        findings += check_tool_integrity(decl, cfg.path)
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
                # Rug-pull fingerprint: drift flags a same-named server whose
                # launch identity (command/args/auto-approve) silently changed.
                tool_identity=tool_identity(decl.command, decl.args, decl.auto_approve),
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
    """Query OSV for every pinned coordinate on a launch command and flag vulns.

    The single pinned *runner* spec keeps its existing ``PIN-KNOWN-VULN`` finding;
    every *other* extracted coordinate (a second dep, a ``python -m`` requirement)
    that OSV flags becomes a ``VULN-KNOWN`` finding. Coordinates are de-duplicated
    so a spec covered by the runner finding is never queried or reported twice
    (Wave 3 Feature V).
    """
    findings: list[Finding] = []
    covered: set[tuple[str, str, str]] = set()

    pinned: PackageSpec | None = parse_package_spec(command, args)
    if pinned is not None:
        covered.add((pinned.ecosystem, pinned.name, pinned.version))
        vuln_ids, critical = osv_fetch(pinned.name, pinned.version, pinned.ecosystem)
        if vuln_ids:
            findings.append(
                known_vuln_finding(server_name, pinned, vuln_ids, config_path, critical=critical)
            )

    for coord in extract_version_coords(command, args):
        key = (coord.ecosystem, coord.name, coord.version)
        if key in covered:
            continue
        covered.add(key)
        vuln_ids, critical = osv_fetch(coord.name, coord.version, coord.ecosystem)
        if vuln_ids:
            findings.append(
                vuln_known_finding(
                    f"Server {server_name!r}", coord, vuln_ids, config_path, critical=critical
                )
            )
    return findings


def _default_osv_fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
    """Real OSV lookup. Imported lazily so egress code never loads by default."""
    from .enrichment.osv import query_osv

    vulns = query_osv(name, version, ecosystem)
    return tuple(v.id for v in vulns), any(v.critical for v in vulns)


def _audit_env_file(env_file: EnvFile, secret_catalog: SecretCatalog | None = None) -> Server:
    findings = check_env_file_secrets(env_file, catalog=secret_catalog) + check_secret_at_rest(
        env_file, catalog=secret_catalog
    )
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


def _posix_file_mode(path: Path) -> int | None:
    """Return ``st_mode & 0o777`` on POSIX, else ``None``.

    The group/world-readable at-rest checks are a POSIX concept. On Windows
    ``chmod`` only toggles the read-only bit and ``st_mode`` reports a fixed
    ``0o666``-ish value, so ``mode & 0o077`` would fire on every file. Returning
    ``None`` off POSIX keeps the perms check from raising a meaningless finding.
    """
    if os.name != "posix":
        return None
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def _file_mtime_epoch(path: Path) -> int | None:
    """Return ``path``'s mtime as whole seconds since the epoch, or ``None``.

    The clock-free half of the telemetry staleness check: the engine reads the
    file time here and the pure check compares it against the CLI-supplied
    ``now_epoch`` — no check reads a clock of its own.
    """
    try:
        return int(path.stat().st_mtime)
    except OSError:
        return None


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


def _audit_token_stores(
    adapters: Sequence[HostAdapter],
    system: str,
    env: Mapping[str, str],
    now_epoch: int | None,
) -> list[Server]:
    """Grade each adapter's on-disk credential store (Feature H; opt-in only).

    Reads only the paths the shared credential-artifact registry
    (``HostAdapter.credential_artifact_paths``) names, each through ``io_safe``
    (traversal-safe, size-capped). The token value never leaves the decode
    boundary: :func:`decode_store` returns only non-secret metadata, so no raw
    token is stored on a finding or printed. A store with safe permissions and no
    expired token yields no finding and is not surfaced — presence is not a
    vulnerability. Deterministic given ``now_epoch`` (supplied by ``cli``).
    """
    servers: list[Server] = []
    seen: set[Path] = set()
    for adapter in adapters:
        for cand in adapter.credential_artifact_paths(system, env):
            path = Path(str(cand))
            if path in seen:
                continue
            seen.add(path)
            if not path.is_file():
                continue
            mode = _posix_file_mode(path)
            raw = _read_config_file(path)
            decoded = decode_store(raw) if raw is not None else None
            findings = check_token_store(
                str(path), mode, present=True, decoded=decoded, now_epoch=now_epoch
            )
            if findings:
                servers.append(
                    Server(
                        id=f"token-store://{path}",
                        bind_addr=None,
                        port=None,
                        pid=None,
                        proc_name=None,
                        state=ServerState.DECLARED,
                        running=False,
                        findings=tuple(findings),
                    )
                )
    return servers


def _telemetry_facts(path: Path) -> tuple[bool, int | None, int | None]:
    """Gather ``(present, mode, mtime_epoch)`` for one telemetry surface.

    Handles a surface that is either a single log file or a directory of logs:

    - a **directory** is "present" only if it holds at least one file; ``mode``
      is the bitwise-OR of the child files' modes (so a single group/world-
      readable log trips the perms rule while the directory's own — normally
      ``0o755`` — mode never causes a false positive), and ``mtime_epoch`` is the
      newest child's mtime;
    - a **file** is "present" only if non-empty (an empty log captures nothing).

    Only metadata is touched — existence, mode, mtime, and (for a directory) the
    child listing. Log *contents* are never read, so no sensitive log data enters
    the pipeline.
    """
    if not path.exists():
        return (False, None, None)
    if path.is_dir():
        try:
            children = [child for child in path.iterdir() if child.is_file()]
        except OSError:
            return (False, None, None)
        if not children:
            return (False, None, None)
        combined: int | None = None
        for child in children:
            child_mode = _posix_file_mode(child)
            if child_mode is not None:
                combined = child_mode if combined is None else combined | child_mode
        mtimes = [t for t in (_file_mtime_epoch(child) for child in children) if t is not None]
        newest = max(mtimes) if mtimes else None
        return (True, combined, newest)
    try:
        empty = path.stat().st_size == 0
    except OSError:
        return (False, None, None)
    if empty:
        return (False, None, None)
    return (True, _posix_file_mode(path), _file_mtime_epoch(path))


def _audit_telemetry(
    adapters: Sequence[HostAdapter],
    system: str,
    env: Mapping[str, str],
    now_epoch: int | None,
) -> list[Server]:
    """Grade each adapter's agent-host log surface (Feature L; opt-in only).

    Reads only the paths the telemetry registry (``HostAdapter.telemetry_surfaces``)
    names, and only their *metadata* — presence, POSIX mode, mtime — never the log
    contents. A surface that is present, owner-only, and fresh yields no finding
    and is not surfaced. Deterministic given ``now_epoch`` (supplied by ``cli``).
    """
    servers: list[Server] = []
    seen: set[Path] = set()
    for adapter in adapters:
        for cand in adapter.telemetry_surfaces(system, env):
            path = Path(str(cand))
            if path in seen:
                continue
            seen.add(path)
            present, mode, mtime_epoch = _telemetry_facts(path)
            findings = check_telemetry(
                str(path),
                present=present,
                mode=mode,
                mtime_epoch=mtime_epoch,
                now_epoch=now_epoch,
            )
            if findings:
                servers.append(
                    Server(
                        id=f"telemetry://{path}",
                        bind_addr=None,
                        port=None,
                        pid=None,
                        proc_name=None,
                        state=ServerState.DECLARED,
                        running=False,
                        findings=tuple(findings),
                    )
                )
    return servers


def _audit_broker(
    subjects: Sequence[tuple[str, ServerDecl]],
    system: str,
    env: Mapping[str, str],
) -> list[Server]:
    """Grade Agent Trust Broker posture over declared servers (Feature; opt-in).

    Reads the single documented broker manifest (``broker.json``, via ``io_safe``)
    and grades whether each privileged server is fronted and whether the broker is
    sound. Assessment-only: it reads the manifest and never writes, enforces, or
    contacts the broker. A missing manifest is the common (unbrokered) case, not
    an error — privileged servers then surface as ``BROKER-ABSENT``. A file that
    exists but is malformed or unreadable degrades to ``BROKER-PARSE-ERROR`` and
    rides ``inspection_incomplete``, never a crash. The manifest carries no
    secrets, so no redaction boundary is crossed. All findings are collected onto
    a single synthetic ``broker://`` server (mirroring the token-store/telemetry
    surfaces); each finding's own location identifies the affected server/manifest.
    """
    candidates = [Path(str(c)) for c in ianua_broker_manifest_candidates(system, env)]
    manifest_file = next((p for p in candidates if p.is_file()), None)
    present = manifest_file is not None

    parsed: BrokerManifest | BrokerParseError | None = None
    if manifest_file is not None:
        raw = _read_config_file(manifest_file)
        # A file that exists but is unreadable (io_safe refusal) is still
        # "present but unreadable" -> a parse error, not a silent absence.
        parsed = (
            parse_broker_manifest(raw)
            if raw is not None
            else BrokerParseError("broker.json could not be read")
        )

    if manifest_file is not None:
        display_path = str(manifest_file)
    elif candidates:
        display_path = str(candidates[0])
    else:
        display_path = "broker.json"

    home = env.get("HOME") or env.get("USERPROFILE")
    findings = check_broker_posture(
        subjects, parsed, present, manifest_path=display_path, home=home
    )
    if not findings:
        return []
    incomplete = isinstance(parsed, BrokerParseError)
    return [
        Server(
            id=f"broker://{display_path}",
            bind_addr=None,
            port=None,
            pid=None,
            proc_name=None,
            state=ServerState.DECLARED,
            running=False,
            inspection_incomplete=incomplete,
            findings=tuple(findings),
        )
    ]


def _audit_process_envs(
    osv_fetch: OsvFetch | None,
    agent_catalog: AgentCatalog | None = None,
    secret_catalog: SecretCatalog | None = None,
) -> list[Server]:
    """Grade secrets in running agent/MCP process environments (Feature G; opt-in).

    Enumerates only the invoking user's own agent/MCP processes (the scope
    guardrail lives in :func:`looks_like_agent`) and reads their environments —
    never every process on the box, and never a non-agent process's env. Each
    process that carries a plaintext secret becomes one synthetic RUNNING server;
    a process with no secret is not surfaced (running an agent is not a
    vulnerability), mirroring the socket-exposure pattern. ``inspection_incomplete``
    from the enumeration (own-user-only visibility, or a process that exited
    mid-scan) rides along on each surfaced server. Secrets are fingerprinted at
    detection, so no raw environment value reaches a finding.

    When ``osv_fetch`` is set (``--online``), each process's cmdline is also
    scanned for known-vulnerable package coordinates (Wave 3 Feature V), so a
    process launched from a vulnerable pinned package is surfaced even with a
    clean environment.
    """
    predicate = (
        looks_like_agent
        if agent_catalog is None
        else (lambda text: looks_like_agent(text, catalog=agent_catalog))
    )
    result = iter_agent_process_envs(predicate)
    servers: list[Server] = []
    for entry in result.entries:
        findings = check_process_env_secrets([entry], catalog=secret_catalog)
        if osv_fetch is not None:
            findings += _enrich_cmdline(entry.proc_name, entry.pid, entry.cmdline, osv_fetch)
        if findings:
            servers.append(
                Server(
                    id=f"process://{entry.proc_name}:{entry.pid}",
                    bind_addr=None,
                    port=None,
                    pid=entry.pid,
                    proc_name=entry.proc_name,
                    state=ServerState.RUNNING,
                    running=True,
                    inspection_incomplete=result.inspection_incomplete,
                    findings=tuple(findings),
                )
            )
    return servers


def _enrich_cmdline(
    proc_name: str,
    pid: int,
    cmdline: str,
    osv_fetch: OsvFetch,
) -> list[Finding]:
    """Query OSV for known-vulnerable coordinates on a process cmdline (Feature V)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    location = f"process://{proc_name}[{pid}]"
    for coord in extract_version_coords_from_cmdline(cmdline):
        key = (coord.ecosystem, coord.name, coord.version)
        if key in seen:
            continue
        seen.add(key)
        vuln_ids, critical = osv_fetch(coord.name, coord.version, coord.ecosystem)
        if vuln_ids:
            findings.append(
                vuln_known_finding(
                    f"Process {proc_name!r}", coord, vuln_ids, location, critical=critical
                )
            )
    return findings


def _active_secret_and_agent_catalogs(
    system: str, env: Mapping[str, str]
) -> tuple[SecretCatalog, AgentCatalog]:
    """Resolve the active detection catalogs once per scan (Feature D).

    A pack installed by ``update-datapack`` (verified at install time, owner-only
    at rest) lives in the OS-appropriate local store; if it is present and still
    parses, its catalogs drive detection. Otherwise — the default case — the
    built-in pack is used, so a scan with no installed pack is byte-identical to
    before. A store that no longer parses falls back to the built-in silently
    (a corrupt store can never crash or weaken a scan below the built-in).
    """
    pack = builtin_datapack()
    store = datapack_store_path(system, env)
    if store is not None:
        local = load_local_datapack(Path(str(store)))
        if local is not None:
            pack = local
    return compile_secret_catalog(pack), compile_agent_catalog(pack)


def scan(
    *,
    roots: Sequence[Path] | None = None,
    system: str | None = None,
    env: Mapping[str, str] | None = None,
    enumerate_sockets: bool = True,
    online: bool = False,
    osv_fetch: OsvFetch | None = None,
    inspect_token_stores: bool = False,
    inspect_process_env: bool = False,
    inspect_telemetry: bool = False,
    inspect_broker: bool = False,
    now_epoch: int | None = None,
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
        inspect_token_stores: When True (opt-in), reads the on-disk credential
            stores named by the shared credential-artifact registry and grades
            their permissions/expiry (Feature H). Default False reads nothing
            new — no default-on file reads.
        inspect_process_env: When True (opt-in), reads the environment blocks of
            the invoking user's own running agent/MCP processes to detect
            plaintext secrets (Feature G). Default False enumerates no processes
            and reads no environments.
        inspect_telemetry: When True (opt-in), reads the *metadata* (existence,
            mode, mtime) of the agent-host log surfaces named by the telemetry
            registry and grades logging health (Feature L). Default False reads
            nothing new; log contents are never read on either path.
        inspect_broker: When True (opt-in), reads the documented Agent Trust
            Broker manifest (``broker.json``) and grades whether privileged
            servers are fronted by a sound broker (ATB_POSTURE_CHECK.md).
            Assessment-only: it reads the manifest and never writes, enforces, or
            contacts the broker. Default False reads nothing new and emits no
            broker findings.
        now_epoch: "Now" in seconds since the epoch, supplied by ``cli`` so the
            token-store expiry and telemetry-staleness grades stay clock-free
            here. Consulted only when ``inspect_token_stores`` or
            ``inspect_telemetry`` is True.
    """
    system = system or platform.system()
    env = env if env is not None else os.environ
    roots = list(roots) if roots is not None else [Path.cwd()]

    fetch: OsvFetch | None = None
    if online:
        fetch = osv_fetch if osv_fetch is not None else _default_osv_fetch

    # Active detection catalogs (built-in, or a verified installed data-pack),
    # resolved once so every check sees the same catalog (Feature D).
    secret_catalog, agent_catalog = _active_secret_and_agent_catalogs(system, env)

    adapters = _adapters()
    servers: list[Server] = []
    # (subject_id, decl) for every declared server, collected only when the
    # opt-in broker audit needs them — the trust-engine identity the manifest's
    # ``fronts`` list is joined against.
    broker_subjects: list[tuple[str, ServerDecl]] = []

    # --- user-level (default) host configs ---
    for adapter in adapters:
        for cand in adapter.default_config_paths(system, env):
            path = Path(str(cand))
            raw = _read_config_file(path)
            if raw is None:
                continue
            parsed = adapter.parse(str(path), raw)
            servers.extend(_audit_config(parsed, fetch, secret_catalog))
            if inspect_broker:
                broker_subjects.extend((f"{parsed.path}#{d.name}", d) for d in parsed.servers)

    # --- project-scoped host configs + .env ---
    for root in roots:
        for adapter in adapters:
            for path in adapter.project_config_paths(root):
                if not path.exists():
                    continue
                raw = _read_config_file(path)
                if raw is None:
                    continue
                parsed = adapter.parse(str(path), raw)
                servers.extend(_audit_config(parsed, fetch, secret_catalog))
                if inspect_broker:
                    broker_subjects.extend((f"{parsed.path}#{d.name}", d) for d in parsed.servers)
        env_path = root / ".env"
        if env_path.exists():
            raw = _read_config_file(env_path)
            if raw is not None:
                env_file = parse_env_text(
                    str(env_path),
                    raw,
                    mode=_posix_file_mode(env_path),
                    git_tracked=_git_tracked(env_path),
                )
                servers.append(_audit_env_file(env_file, secret_catalog))

    # --- credential/token stores at rest (opt-in; zero new reads by default) ---
    if inspect_token_stores:
        servers.extend(_audit_token_stores(adapters, system, env, now_epoch))

    # --- secrets in running agent-process environments (opt-in; zero by default) ---
    if inspect_process_env:
        servers.extend(_audit_process_envs(fetch, agent_catalog, secret_catalog))

    # --- agent-host logging health (opt-in; zero new reads by default) ---
    if inspect_telemetry:
        servers.extend(_audit_telemetry(adapters, system, env, now_epoch))

    # --- Agent Trust Broker posture / governance (opt-in; zero new reads by default) ---
    if inspect_broker:
        servers.extend(_audit_broker(broker_subjects, system, env))

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
