# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Credential-hygiene checks (T-206 detection, T-207 at-rest, blast radius).

Detects plaintext secrets in server ``env`` blocks, ``.env`` files, and the
environments of running agent/MCP processes (by known provider patterns and by
high-entropy values on secret-named keys), and flags secret-bearing files that
are world/group-readable or git-tracked. Every detected secret is reduced to a
fingerprint immediately (R1) — the raw value never leaves this module.
``check_secret_reuse`` then joins those fingerprints across servers to surface
the blast radius of one credential living in several places.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from ..adapters.base import ServerDecl
from ..datapack import SecretCatalog, builtin_secret_catalog
from ..discovery.process_env import ProcessEnv
from ..domain import Dimension, Finding, Location, SecretFingerprint, Server, Severity
from ..redaction import fingerprint_secret
from . import EnvFile

# The provider-pattern / secret-name / entropy catalog now lives in
# ``mcpscan.datapack`` (the built-in pack is byte-identical to the constants that
# used to sit here), so the opt-in signed data-pack channel can refresh detection
# between releases. Each check takes the compiled catalog as a keyword argument
# defaulting to the built-in, keeping every existing call site behaviour-identical.


def shannon_entropy(value: str) -> float:
    """Shannon entropy (bits/char) of a string."""
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _provider_match(value: str, catalog: SecretCatalog) -> str | None:
    for label, pattern in catalog.provider_patterns:
        if pattern.search(value):
            return label
    return None


def _looks_secret(key: str, value: str, catalog: SecretCatalog | None = None) -> str | None:
    """Return a human label if (key, value) looks like a plaintext secret."""
    cat = catalog if catalog is not None else builtin_secret_catalog()
    label = _provider_match(value, cat)
    if label is not None:
        return label
    if (
        cat.secret_name.search(key)
        and len(value) >= cat.min_entropy_len
        and shannon_entropy(value) >= cat.entropy_threshold
    ):
        return "High-entropy secret"
    return None


def _finding(label: str, location: Location, raw_value: str) -> Finding:
    return Finding(
        id="CRED-PLAINTEXT",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.CRITICAL,
        title=f"Plaintext {label} in config",
        location=location,
        remediation=(
            "Remove the literal value from the file. Reference it from a secret "
            "manager or an environment variable resolved at runtime, and rotate "
            "the exposed credential."
        ),
        rationale="Plaintext credentials in agent config are trivially exfiltrated.",
        secret=fingerprint_secret(raw_value),
    )


def check_server_env(
    server: ServerDecl, config_path: str, *, catalog: SecretCatalog | None = None
) -> list[Finding]:
    """Detect plaintext secrets in a declared server's ``env`` block."""
    findings: list[Finding] = []
    for key, value in server.env:
        label = _looks_secret(key, value, catalog)
        if label is not None:
            findings.append(_finding(label, Location(path=config_path), value))
    return findings


def check_env_file_secrets(
    env_file: EnvFile, *, catalog: SecretCatalog | None = None
) -> list[Finding]:
    """Detect plaintext secrets in a parsed ``.env`` file."""
    findings: list[Finding] = []
    for lineno, key, value in env_file.entries:
        label = _looks_secret(key, value, catalog)
        if label is not None:
            findings.append(_finding(label, Location(path=env_file.path, line=lineno), value))
    return findings


def _process_env_finding(label: str, proc_name: str, pid: int, raw_value: str) -> Finding:
    return Finding(
        id="CRED-ENV",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.HIGH,
        title=f"Plaintext {label} in running process env",
        location=Location(path=f"process://{proc_name}[{pid}]"),
        remediation=(
            "Pass secrets to the process from a broker or secret manager at "
            "runtime rather than baking them into the process environment, and "
            "rotate the exposed credential."
        ),
        rationale=(
            "A secret in a running process's environment is legible to anything "
            "that can read the process (e.g. /proc/<pid>/environ) — a live, "
            "already-loaded credential an attacker can lift without touching disk."
        ),
        secret=fingerprint_secret(raw_value),
    )


def check_process_env_secrets(
    entries: Sequence[ProcessEnv], *, catalog: SecretCatalog | None = None
) -> list[Finding]:
    """Detect plaintext secrets in the environments of running agent processes.

    Pure over its inputs (the psutil edge lives in ``discovery.process_env``):
    reuses the same ``_looks_secret`` heuristic as the config/``.env`` checks, so
    detection is consistent across surfaces. Every hit is reduced to a
    :class:`~mcpscan.domain.SecretFingerprint` at detection — the raw environment
    value never leaves this function on the finding.
    """
    findings: list[Finding] = []
    for entry in entries:
        for key, value in entry.env:
            label = _looks_secret(key, value, catalog)
            if label is not None:
                findings.append(_process_env_finding(label, entry.proc_name, entry.pid, value))
    return findings


def check_secret_at_rest(
    env_file: EnvFile, *, catalog: SecretCatalog | None = None
) -> list[Finding]:
    """Flag a secret-bearing ``.env`` that is world/group-readable or tracked."""
    findings: list[Finding] = []
    has_secret = any(_looks_secret(k, v, catalog) is not None for _, k, v in env_file.entries)
    if not has_secret:
        return findings

    if env_file.mode is not None and env_file.mode & 0o077:
        findings.append(
            Finding(
                id="CRED-PERMS",
                dimension=Dimension.CREDENTIAL,
                severity=Severity.HIGH,
                title="Secret file is group/world-readable",
                location=Location(path=env_file.path),
                remediation="Restrict permissions: chmod 600 the file.",
                rationale="Other local users/processes can read the secrets.",
            )
        )
    if env_file.git_tracked:
        findings.append(
            Finding(
                id="CRED-GIT",
                dimension=Dimension.CREDENTIAL,
                severity=Severity.HIGH,
                title="Secret file is tracked by git",
                location=Location(path=env_file.path),
                remediation="Remove from git history and add the file to .gitignore.",
                rationale="Committed secrets leak to anyone with repo access.",
            )
        )
    return findings


def _reuse_finding(
    sha256_8: str,
    n_locations: int,
    own_path: str,
    other_paths: Sequence[str],
    own_fingerprint: SecretFingerprint,
) -> Finding:
    return Finding(
        id="CRED-REUSE",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.MEDIUM,
        title=f"Secret reused across {n_locations} locations",
        location=Location(path=own_path),
        remediation=("Issue distinct credentials per server so one compromise cannot pivot."),
        rationale=(
            f"A secret with fingerprint sha256:{sha256_8} also appears at: "
            + ", ".join(other_paths)
            + ". Compromising any one holder exposes every location sharing it."
        ),
        secret=own_fingerprint,
    )


def check_secret_reuse(servers: Sequence[Server]) -> dict[str, list[Finding]]:
    """Blast-radius join: the same secret fingerprint on two or more servers.

    Joins every finding-carried :class:`~mcpscan.domain.SecretFingerprint` across
    the given servers on ``(sha256_8, length)``. When one key appears on >= 2
    distinct server ids, each involved server gains one MEDIUM ``CRED-REUSE``
    finding. The rationale names the *other* locations by path only, plus the
    shared ``sha256_8`` — the operator triage handle, already redaction-safe;
    another finding's mask is never repeated here, and each emitted finding
    carries only its own server's fingerprint.

    Collision caveat (same stance as :class:`~mcpscan.domain.SecretFingerprint`):
    ``sha256_8`` is a 32-bit truncation, so a false pairing between two distinct
    secrets is possible. The finding is therefore triage-level (MEDIUM), not
    proof of reuse.

    Pure and deterministic: no I/O; ordering is fixed by sorted fingerprints and
    sorted paths. Returns a ``server id -> findings to append`` mapping so the
    engine can merge additions before grading.
    """
    occurrences: dict[tuple[str, int], list[tuple[str, SecretFingerprint, str]]] = {}
    for server in servers:
        for finding in server.findings:
            fp = finding.secret
            if fp is None:
                continue
            key = (fp.sha256_8, fp.length)
            occurrences.setdefault(key, []).append((server.id, fp, finding.location.path))

    additions: dict[str, list[Finding]] = {}
    for (sha256_8, _length), seen in sorted(occurrences.items()):
        involved = sorted({server_id for server_id, _, _ in seen})
        if len(involved) < 2:
            continue
        for server_id in involved:
            own_fp, own_path = next((fp, path) for sid, fp, path in seen if sid == server_id)
            other_paths = sorted({path for sid, _, path in seen if sid != server_id})
            additions.setdefault(server_id, []).append(
                _reuse_finding(sha256_8, len(involved), own_path, other_paths, own_fp)
            )
    return additions
