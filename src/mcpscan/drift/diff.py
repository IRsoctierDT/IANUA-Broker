# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Compare two snapshots into a :class:`DriftReport` (VISION Tier 5).

Pure set-difference over posture facts by their stable key, plus a **direction**
for each change so a CI gate can act on regressions only:

- a **new finding** or a **newly-exposed** server is a REGRESSION (posture worse);
- a **resolved finding** or a server that **stopped being exposed** is an
  IMPROVEMENT;
- a server whose ``inspection_incomplete`` flips false→true is a REGRESSION —
  the scanner **lost visibility it previously had**. No finding appeared, which
  is exactly why it matters: silent collection failure is the more dangerous
  half of drift. The reverse flip (visibility regained) is an IMPROVEMENT;
- a declared server whose ``tool_identity`` fingerprint changed under the **same
  name** is a REGRESSION — same server, silently changed code/tools (a possible
  rug-pull). Like visibility loss it must never render green, so it outranks an
  exposure improvement that happens in the same scan;
- everything else — a new/removed asset, a declared server appearing — is
  INFORMATIONAL.

Every entry also carries a :class:`DriftCause` naming the degradation class
behind it (config/permission, provenance, exposure, inspection, inventory), so
reports speak the Blue Report's cause vocabulary instead of a bare add/remove.

The asymmetry is deliberate: findings are problems, so *gaining* one is bad and
*losing* one is good; assets are inventory, so their coming and going is just
news. A control that disappears shows up here as a **new finding** (the check
that the control was present now fires), which is why added findings are the
core regression signal.

Compatibility: baselines written before the ``inspection_incomplete`` detail
key existed are treated as if the key were ``"false"`` — an old fact lacking
the key diffs clean against a current fact that says ``"false"``, so upgrading
the scanner never manufactures phantom drift. The ``tool_identity`` key (Wave 3)
has no natural default, so it is *compat-optional*: it is dropped from the
comparison whenever either side omits it, making a pre-Wave-3 baseline diff
clean against a current fact that now carries an identity.
"""

from __future__ import annotations

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


def _exposure_of(fact: PostureFact) -> str:
    return fact.detail_map().get("exposure", "")


def _inspection_incomplete(fact: PostureFact) -> bool:
    # Absent means "false": pre-1.5 baselines predate the key.
    return fact.detail_map().get("inspection_incomplete", "false") == "true"


# Detail keys that arrived without a natural default value, so they cannot be
# back-filled the way ``inspection_incomplete`` is. They are dropped from the
# comparison whenever either side lacks them, so a baseline predating the key
# never manufactures phantom drift ("absent == unchanged").
_COMPAT_OPTIONAL_KEYS: tuple[str, ...] = ("tool_identity",)


def _comparable_detail(fact: PostureFact) -> tuple[tuple[str, str], ...]:
    """A fact's detail with compat defaults filled in, for change comparison.

    Server facts gained ``inspection_incomplete`` after schema 1.0 shipped;
    older baselines omit it. Filling in ``"false"`` here keeps an unchanged
    posture diffing clean against a pre-key baseline.
    """
    if fact.kind is not FactKind.SERVER:
        return fact.detail
    detail = fact.detail_map()
    detail.setdefault("inspection_incomplete", "false")
    return tuple(sorted(detail.items()))


def _aligned_details(
    before: PostureFact, after: PostureFact
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    """The two facts' comparable details, with compat-optional keys aligned.

    A compat-optional key (e.g. ``tool_identity``) is stripped from **both** sides
    when **either** side omits it. That makes "absent == unchanged": a pre-Wave-3
    baseline that never recorded ``tool_identity`` diffs clean against a current
    fact that now carries one, so an upgrade never manufactures a phantom
    rug-pull. When both sides carry the key, a real change survives and drives a
    CHANGED entry.
    """
    b = dict(_comparable_detail(before))
    a = dict(_comparable_detail(after))
    for key in _COMPAT_OPTIONAL_KEYS:
        if key not in b or key not in a:
            b.pop(key, None)
            a.pop(key, None)
    return tuple(sorted(b.items())), tuple(sorted(a.items()))


def _tool_identity_changed(before: PostureFact, after: PostureFact) -> bool:
    """True when a same-named server's launch fingerprint changed (possible rug-pull).

    Only a change between two *present* identities counts. An identity present on
    one side and absent on the other is a schema-era difference, not a rug-pull,
    so it is ignored (see :func:`_aligned_details`).
    """
    before_id = before.detail_map().get("tool_identity")
    after_id = after.detail_map().get("tool_identity")
    return before_id is not None and after_id is not None and before_id != after_id


def _finding_cause(fact: PostureFact) -> DriftCause:
    detail = fact.detail_map()
    finding_id = detail.get("id") or fact.summary.split(" — ", 1)[0]
    if finding_id.startswith("PIN-"):
        return DriftCause.PROVENANCE_DRIFT
    if detail.get("dimension") == "exposure" or finding_id.startswith(("EXP-", "EXPOSE-")):
        return DriftCause.EXPOSURE_DRIFT
    if finding_id.startswith(("CRED-", "SCOPE-")):
        return DriftCause.CONFIG_DRIFT
    return DriftCause.OTHER


def _classify_added(fact: PostureFact) -> tuple[Direction, DriftCause]:
    if fact.kind is FactKind.FINDING:
        return Direction.REGRESSION, _finding_cause(fact)
    if fact.kind is FactKind.ASSET:
        return Direction.INFORMATIONAL, DriftCause.INVENTORY_DRIFT
    if _exposure_of(fact) == "exposed":
        return Direction.REGRESSION, DriftCause.EXPOSURE_DRIFT
    return Direction.INFORMATIONAL, DriftCause.OTHER


def _classify_removed(fact: PostureFact) -> tuple[Direction, DriftCause]:
    if fact.kind is FactKind.FINDING:
        return Direction.IMPROVEMENT, _finding_cause(fact)
    if fact.kind is FactKind.ASSET:
        return Direction.INFORMATIONAL, DriftCause.INVENTORY_DRIFT
    if _exposure_of(fact) == "exposed":
        return Direction.INFORMATIONAL, DriftCause.EXPOSURE_DRIFT
    return Direction.INFORMATIONAL, DriftCause.OTHER


def _classify_changed(before: PostureFact, after: PostureFact) -> tuple[Direction, DriftCause]:
    if after.kind is FactKind.FINDING:
        return Direction.INFORMATIONAL, _finding_cause(after)
    if after.kind is FactKind.ASSET:
        return Direction.INFORMATIONAL, DriftCause.INVENTORY_DRIFT
    # SERVER: regressions outrank improvements, and visibility loss outranks
    # everything — an "improvement" observed with degraded inspection may be
    # the degradation itself, so it must never render as a green entry.
    was, now = _exposure_of(before), _exposure_of(after)
    was_dark, now_dark = _inspection_incomplete(before), _inspection_incomplete(after)
    if not was_dark and now_dark:
        # Visibility lost: a regression with no finding attached — the silent
        # failure a green-looking diff would otherwise hide.
        return Direction.REGRESSION, DriftCause.INSPECTION_REGRESSION
    if was != "exposed" and now == "exposed":
        return Direction.REGRESSION, DriftCause.EXPOSURE_DRIFT
    if _tool_identity_changed(before, after):
        # Same server name, changed command/args/auto-approve: a possible
        # rug-pull. A regression even when nothing else moved, and it must never
        # render green because the server also happened to stop being exposed.
        return Direction.REGRESSION, DriftCause.TOOL_IDENTITY_DRIFT
    if was == "exposed" and now != "exposed":
        return Direction.IMPROVEMENT, DriftCause.EXPOSURE_DRIFT
    if was_dark and not now_dark:
        return Direction.IMPROVEMENT, DriftCause.INSPECTION_REGRESSION
    return Direction.INFORMATIONAL, DriftCause.OTHER


def diff_snapshots(baseline: Snapshot, current: Snapshot) -> DriftReport:
    """Diff a baseline snapshot against a current one."""
    old = baseline.by_key()
    new = current.by_key()
    entries: list[DriftEntry] = []

    for key in new.keys() - old.keys():
        fact = new[key]
        direction, cause = _classify_added(fact)
        entries.append(
            DriftEntry(
                change=ChangeType.ADDED,
                kind=fact.kind,
                key=key,
                summary=fact.summary,
                direction=direction,
                cause=cause,
                detail_after=_comparable_detail(fact),
            )
        )

    for key in old.keys() - new.keys():
        fact = old[key]
        direction, cause = _classify_removed(fact)
        entries.append(
            DriftEntry(
                change=ChangeType.REMOVED,
                kind=fact.kind,
                key=key,
                summary=fact.summary,
                direction=direction,
                cause=cause,
                detail_before=_comparable_detail(fact),
            )
        )

    for key in old.keys() & new.keys():
        before, after = old[key], new[key]
        detail_before, detail_after = _aligned_details(before, after)
        if detail_before == detail_after:
            continue
        direction, cause = _classify_changed(before, after)
        entries.append(
            DriftEntry(
                change=ChangeType.CHANGED,
                kind=after.kind,
                key=key,
                summary=after.summary,
                direction=direction,
                cause=cause,
                detail_before=detail_before,
                detail_after=detail_after,
            )
        )

    entries.sort(key=lambda e: (_DIRECTION_ORDER[e.direction], e.kind.value, e.key))
    return DriftReport(entries=tuple(entries))


_DIRECTION_ORDER = {
    Direction.REGRESSION: 0,
    Direction.IMPROVEMENT: 1,
    Direction.INFORMATIONAL: 2,
}
