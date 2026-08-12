# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure model for configuration-drift detection (VISION Tier 5).

A :class:`Snapshot` is a normalized, comparable view of the machine's posture at
one point in time — a flat set of :class:`PostureFact`s, each with a **stable
key** (so the same server/finding/asset lines up across snapshots) and a
comparable ``detail``. :func:`diff_snapshots` turns two snapshots into a
:class:`DriftReport` of what appeared, disappeared, or changed.

Like ``domain``, this module is frozen and contains no I/O. Snapshots are built
from a scan ``Report`` (and optionally an ``Inventory``) in ``snapshot.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

DRIFT_SCHEMA_VERSION = "1.0"


class FactKind(Enum):
    """What a posture fact describes."""

    SERVER = "server"  # a discovered server/endpoint (running or declared)
    FINDING = "finding"  # a posture finding at a location
    ASSET = "asset"  # an inventoried AI/MCP asset


class Direction(Enum):
    """Whether a drift entry makes posture worse, better, or neither.

    ``REGRESSION`` is the one that matters for a CI gate: a new finding, or a
    newly-exposed surface, means posture got worse against the baseline.
    """

    REGRESSION = "regression"
    IMPROVEMENT = "improvement"
    INFORMATIONAL = "informational"


class ChangeType(Enum):
    """How a fact changed between two snapshots."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class DriftCause(Enum):
    """Why posture drifted — the Blue Report's degradation-cause vocabulary.

    Each drift entry names the class of change behind it, so a reader can tell
    a permission edit from a supply-chain change from a network exposure shift.
    ``INSPECTION_REGRESSION`` is the silent-failure class: the scanner lost
    visibility it previously had, which is a regression even though no finding
    appeared — collection failing quietly is the more dangerous half of drift.
    """

    CONFIG_DRIFT = "config_drift"  # config/permission change
    PROVENANCE_DRIFT = "provenance_drift"  # package/version provenance change
    EXPOSURE_DRIFT = "exposure_drift"  # network exposure change
    INSPECTION_REGRESSION = "inspection_regression"  # scanner lost visibility it had
    INVENTORY_DRIFT = "inventory_drift"  # an inventoried asset appeared/disappeared
    TOOL_IDENTITY_DRIFT = "tool_identity_drift"  # same server name, changed code/tools (rug-pull)
    OTHER = "other"


@dataclass(frozen=True)
class PostureFact:
    """One normalized, comparable posture observation.

    ``key`` is the stable identity used to line facts up across snapshots;
    ``detail`` is the comparable payload (sorted, JSON-safe scalars only) whose
    change marks a CHANGED entry. ``summary`` is a short human label.
    """

    kind: FactKind
    key: str
    summary: str
    detail: tuple[tuple[str, str], ...] = ()  # sorted (name, value) pairs

    def detail_map(self) -> dict[str, str]:
        return dict(self.detail)


@dataclass(frozen=True)
class Snapshot:
    """A normalized posture at one point in time."""

    schema_version: str
    facts: tuple[PostureFact, ...] = field(default_factory=tuple)

    def by_key(self) -> dict[str, PostureFact]:
        return {f.key: f for f in self.facts}


@dataclass(frozen=True)
class DriftEntry:
    """One change between two snapshots, with its posture direction and cause."""

    change: ChangeType
    kind: FactKind
    key: str
    summary: str
    direction: Direction
    cause: DriftCause = DriftCause.OTHER
    detail_before: tuple[tuple[str, str], ...] = ()
    detail_after: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class DriftReport:
    """The full set of changes from a baseline snapshot to a current one."""

    entries: tuple[DriftEntry, ...] = field(default_factory=tuple)

    @property
    def regressions(self) -> tuple[DriftEntry, ...]:
        return tuple(e for e in self.entries if e.direction is Direction.REGRESSION)

    @property
    def improvements(self) -> tuple[DriftEntry, ...]:
        return tuple(e for e in self.entries if e.direction is Direction.IMPROVEMENT)

    @property
    def has_drift(self) -> bool:
        return bool(self.entries)
