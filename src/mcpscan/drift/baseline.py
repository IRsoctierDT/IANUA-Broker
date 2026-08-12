# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Serialize a Snapshot to a baseline file, and load one back with an integrity check.

The baseline is byte-stable JSON: the same posture always writes the same bytes
(``created_at`` metadata aside), so it diffs cleanly in version control. On load,
the stored digest is recomputed from the facts — a mismatch means the file was
edited or corrupted, and the caller can refuse to trust it.
"""

from __future__ import annotations

import json

from .model import DRIFT_SCHEMA_VERSION, FactKind, PostureFact, Snapshot
from .snapshot import snapshot_digest


class BaselineError(Exception):
    """A baseline file that could not be parsed or failed its integrity check."""


def snapshot_to_dict(snapshot: Snapshot, *, created_at: str | None = None) -> dict[str, object]:
    """A JSON-serializable baseline dict. ``created_at`` is metadata (not hashed)."""
    return {
        "tool": "ai-agentic-mcpscan",
        "schema_version": snapshot.schema_version,
        "created_at": created_at,
        "digest": snapshot_digest(snapshot),
        "facts": [
            {
                "kind": f.kind.value,
                "key": f.key,
                "summary": f.summary,
                "detail": dict(f.detail),
            }
            for f in snapshot.facts
        ],
    }


def render_baseline(snapshot: Snapshot, *, created_at: str | None = None) -> str:
    """Render a baseline as deterministic, byte-stable JSON text."""
    return (
        json.dumps(snapshot_to_dict(snapshot, created_at=created_at), indent=2, sort_keys=True)
        + "\n"
    )


def baseline_created_at(text: str) -> str | None:
    """The baseline's ``created_at`` metadata string, or ``None`` if unreadable.

    Deliberately tolerant: ``created_at`` is advisory metadata (not covered by
    the integrity digest), so a missing, null, or non-string field — or even
    malformed JSON — degrades to ``None`` ("unknown age") rather than an error.
    Integrity and shape validation stay :func:`load_baseline`'s job.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    created = data.get("created_at")
    return created if isinstance(created, str) else None


def load_baseline(text: str, *, verify_digest: bool = True) -> Snapshot:
    """Parse a baseline file back into a Snapshot, verifying its integrity digest.

    Raises:
        BaselineError: if the JSON is malformed, the schema is unknown, or the
            recomputed digest does not match the stored one.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise BaselineError(f"malformed baseline JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineError("baseline is not a JSON object")

    schema = data.get("schema_version")
    if schema != DRIFT_SCHEMA_VERSION:
        raise BaselineError(f"unsupported baseline schema_version {schema!r}")

    raw_facts = data.get("facts")
    if not isinstance(raw_facts, list):
        raise BaselineError("baseline 'facts' is not a list")

    facts: list[PostureFact] = []
    for item in raw_facts:
        facts.append(_fact_from_dict(item))
    snapshot = Snapshot(schema_version=DRIFT_SCHEMA_VERSION, facts=tuple(facts))

    if verify_digest:
        stored = data.get("digest")
        actual = snapshot_digest(snapshot)
        if stored != actual:
            raise BaselineError(
                "baseline integrity check failed: digest mismatch "
                "(the file was edited or corrupted)"
            )
    return snapshot


def _fact_from_dict(item: object) -> PostureFact:
    if not isinstance(item, dict):
        raise BaselineError("a baseline fact is not an object")
    try:
        kind = FactKind(item["kind"])
        key = str(item["key"])
        summary = str(item["summary"])
        detail_obj = item.get("detail", {})
    except (KeyError, ValueError) as exc:
        raise BaselineError(f"invalid baseline fact: {exc}") from exc
    if not isinstance(detail_obj, dict):
        raise BaselineError("a baseline fact 'detail' is not an object")
    detail = tuple(sorted((str(k), str(v)) for k, v in detail_obj.items()))
    return PostureFact(kind=kind, key=key, summary=summary, detail=detail)
