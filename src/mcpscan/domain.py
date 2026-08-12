# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure domain model for AI Agentic MCPscan (ticket T-102).

These types are the shared vocabulary of the whole tool. They are **frozen** and
use enums so invariants hold by construction, and they contain **no I/O** — the
entire module is unit-testable without a filesystem or network.

Security note (architecture refinement R1): there is intentionally **no field
that holds a raw secret value**. A detected secret is represented only by a
:class:`SecretFingerprint`, so no downstream renderer can leak it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Finding severity, ordered most-to-least serious by ``weight``."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Point deduction used by the scoring rubric (SPEC §6)."""
        return _SEVERITY_WEIGHT[self]


_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


class Dimension(Enum):
    """The four posture dimensions a finding can belong to."""

    EXPOSURE = "exposure"
    CREDENTIAL = "credential"
    TOOL_SCOPE = "tool_scope"
    PINNING = "pinning"


class ServerState(Enum):
    """Whether a server was observed running or only declared in config."""

    RUNNING = "running"
    DECLARED = "declared"


@dataclass(frozen=True)
class SecretFingerprint:
    """A non-reversible, share-safe stand-in for a detected secret.

    ``masked`` reveals at most the first two and last two characters;
    ``sha256_8`` is an 8-hex-char (32-bit) truncation for operator triage only —
    it is **not** a security control. The raw secret never reaches this object.
    """

    masked: str
    sha256_8: str
    length: int


@dataclass(frozen=True)
class Location:
    """Where a finding was observed."""

    path: str
    line: int | None = None


@dataclass(frozen=True)
class Acceptance:
    """A named-human, expiring risk acceptance attached to a finding.

    Comes from the per-root ``.mcpscan-accept.json`` ledger (see
    ``mcpscan.acceptance``). ``expired`` is computed **once**, at application
    time, from the CLI-supplied ``today`` — so renderers and the exit gate stay
    pure, deterministic functions of the Report with no clock reads of their
    own.

    Gate-vs-grade stance: an unexpired acceptance only stops the finding from
    failing the CLI exit gate. Grades still count accepted findings — posture
    is what it is; acceptance relaxes CI failure, not the measurement.
    """

    owner: str
    accepted: str
    expires: str
    reason: str
    expired: bool = False


@dataclass(frozen=True)
class Finding:
    """A single posture issue, with its remediation guidance."""

    id: str
    dimension: Dimension
    severity: Severity
    title: str
    location: Location
    remediation: str
    rationale: str
    secret: SecretFingerprint | None = None
    acceptance: Acceptance | None = None


@dataclass(frozen=True)
class Server:
    """An MCP server, running or declared, with its findings."""

    id: str
    bind_addr: str | None
    port: int | None
    pid: int | None
    proc_name: str | None
    state: ServerState
    running: bool
    inspection_incomplete: bool = False
    findings: tuple[Finding, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Report:
    """The full result of one scan — a pure function of its inputs."""

    schema_version: str
    servers: tuple[Server, ...]
    overall_grade: str
    dimension_grades: dict[Dimension, str]
    generated_with_online: bool = False
