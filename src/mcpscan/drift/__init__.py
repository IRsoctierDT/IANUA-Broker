# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Configuration-drift detection (VISION Tier 5): baseline, then diff.

``build_snapshot`` normalizes a scan (and optional inventory) into a comparable
:class:`Snapshot`; ``render_baseline`` / ``load_baseline`` persist it with an
integrity digest; ``diff_snapshots`` reports what drifted, flagging regressions
for a CI gate; ``assess_staleness`` judges the baseline's validation age, so a
diff can warn that posture decays without re-validation. Offline and read-only —
it writes only the baseline you ask for.
"""

from .baseline import BaselineError, baseline_created_at, load_baseline, render_baseline
from .diff import diff_snapshots
from .model import (
    ChangeType,
    Direction,
    DriftCause,
    DriftEntry,
    DriftReport,
    FactKind,
    PostureFact,
    Snapshot,
)
from .snapshot import build_snapshot, snapshot_digest, tool_identity
from .staleness import StalenessVerdict, assess_staleness

__all__ = [
    "BaselineError",
    "ChangeType",
    "Direction",
    "DriftCause",
    "DriftEntry",
    "DriftReport",
    "FactKind",
    "PostureFact",
    "Snapshot",
    "StalenessVerdict",
    "assess_staleness",
    "baseline_created_at",
    "build_snapshot",
    "diff_snapshots",
    "load_baseline",
    "render_baseline",
    "snapshot_digest",
    "tool_identity",
]
