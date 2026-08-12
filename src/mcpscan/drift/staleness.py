# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Validation-age staleness for baselines: "last validated N days ago".

Pure and deterministic: :func:`assess_staleness` takes the clock as a parameter
(``today``), so "now" is computed once in the CLI and everything here stays
testable — no ``datetime.now()`` outside the CLI layer. A baseline older than
``max_age_days`` is **stale** (posture decays without re-validation; strong
performance is rented, not owned); a baseline with no readable ``created_at``
metadata is **unknown**, which renders loudly but never trips the opt-in gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime


@dataclass(frozen=True)
class StalenessVerdict:
    """How old a baseline is relative to the accepted re-validation cadence.

    ``created_at`` is the raw metadata string from the baseline (or ``None``);
    ``created_date`` / ``age_days`` are ``None`` when that metadata is absent
    or unparseable — the *unknown* verdict.
    """

    created_at: str | None
    created_date: date | None
    age_days: int | None
    max_age_days: int

    @property
    def known(self) -> bool:
        """Whether the baseline's age could be measured at all."""
        return self.age_days is not None

    @property
    def stale(self) -> bool:
        """True when the measured age exceeds ``max_age_days``.

        Unknown age is *not* stale: the ``--fail-on-stale`` gate is an explicit
        opt-in on measured age, so missing ``created_at`` metadata renders as
        "unknown" in the report instead of silently tripping the gate.
        """
        return self.age_days is not None and self.age_days > self.max_age_days


def assess_staleness(created_at: str | None, *, today: date, max_age_days: int) -> StalenessVerdict:
    """Judge a baseline's validation age against ``max_age_days``.

    Deterministic: ``today`` is injected by the caller (the CLI computes it
    once from UTC wall clock); no clock is read here. An absent or unparseable
    ``created_at`` yields the unknown verdict rather than an error — staleness
    is advisory metadata, and integrity is ``load_baseline``'s job.
    """
    created_date = _parse_iso_date(created_at)
    if created_date is None:
        return StalenessVerdict(
            created_at=created_at, created_date=None, age_days=None, max_age_days=max_age_days
        )
    return StalenessVerdict(
        created_at=created_at,
        created_date=created_date,
        age_days=(today - created_date).days,
        max_age_days=max_age_days,
    )


def _parse_iso_date(created_at: str | None) -> date | None:
    """The calendar date of an ISO-8601 timestamp (or date), else ``None``."""
    if not created_at:
        return None
    try:
        return datetime.fromisoformat(created_at).date()
    except ValueError:
        return None
