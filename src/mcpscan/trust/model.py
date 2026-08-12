# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure model for agent trust analysis (VISION Tier 4).

Where ``scan`` grades *hygiene* and ``inventory`` names *what exists*, trust
analysis answers *what an agent's tools are trusted to do and access* — and,
crucially, which **combinations** of those powers make a tool a lateral-movement
risk. Each MCP server is a trust subject with a **Trust Score** (0–100, higher =
more trustworthy) and a set of :class:`RiskRelationship`s.

Frozen, enum-driven, no I/O. Trust profiles are built from parsed configs in
``analyze.py``; a profile never carries a raw secret (only a count).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

TRUST_SCHEMA_VERSION = "1.0"


class TrustFactor(Enum):
    """A dimension of what an agent's tool is trusted with."""

    SECRET_ACCESS = "secret_access"  # holds credentials in its environment  # nosec B105 - factor name, not a password
    TOOL_PRIVILEGE = "tool_privilege"  # dangerous / wildcard tool grants
    AUTONOMY = "autonomy"  # auto-approves tools (acts without a human gate)
    CODE_PROVENANCE = "code_provenance"  # runs unpinned / remotely-fetched code
    EXPOSURE_REACH = "exposure_reach"  # binds to a network-reachable address


@dataclass(frozen=True)
class FactorScore:
    """One trust factor's contribution to a subject's risk."""

    factor: TrustFactor
    risk: int  # risk points this factor adds (0 = not present)
    detail: str  # short human explanation of the evidence

    @property
    def present(self) -> bool:
        return self.risk > 0


@dataclass(frozen=True)
class RiskRelationship:
    """A dangerous *combination* of trust factors on one subject.

    This is the trust-analysis differentiator: not "the tool has secrets" or
    "the tool auto-approves", but "the tool auto-approves **and** holds secrets"
    — a compromise blast-radius that no single hygiene check surfaces.
    """

    id: str
    title: str
    rationale: str
    factors: tuple[TrustFactor, ...]


@dataclass(frozen=True)
class TrustProfile:
    """The trust standing of one MCP server (the agent's tool provider)."""

    subject: str  # server id, e.g. "~/.mcp.json#db"
    server_name: str
    host: str  # the agent host whose config declared it
    location: str  # config path
    score: int  # 0–100, higher = more trustworthy
    grade: str  # A–F
    factors: tuple[FactorScore, ...] = ()
    relationships: tuple[RiskRelationship, ...] = ()

    @property
    def present_factors(self) -> tuple[FactorScore, ...]:
        return tuple(f for f in self.factors if f.present)


@dataclass(frozen=True)
class TrustReport:
    """The full trust analysis across every discovered agent tool."""

    schema_version: str
    profiles: tuple[TrustProfile, ...] = field(default_factory=tuple)
    overall_grade: str = "A"

    @property
    def risky(self) -> tuple[TrustProfile, ...]:
        """Profiles carrying at least one risk relationship, worst score first."""
        risky = [p for p in self.profiles if p.relationships]
        return tuple(sorted(risky, key=lambda p: p.score))
