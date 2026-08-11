# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Guard: docs/STATUS.md must stay in sync with docs/STATUS.yaml.

STATUS.yaml is the source of truth; STATUS.md is a hand-maintained view. These
tests fail if the two drift on ticket coverage or status, so the Markdown can't
silently fall behind the YAML.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_DOCS = Path(__file__).resolve().parent.parent / "docs"

# Mirror of the legend in STATUS.md: every YAML status maps to one MD icon.
_STATUS_ICONS = {
    "done": "✅",
    "done_doc": "📄",
    "partial": "🟡",
    "pending": "⏳",
    "unverified": "❓",
}


def _yaml_ticket_statuses() -> dict[str, str]:
    data = yaml.safe_load((_DOCS / "STATUS.yaml").read_text(encoding="utf-8"))
    return {t["id"]: t["status"] for sprint in data["sprints"] for t in sprint["tickets"]}


def _md_ticket_rows() -> dict[str, str]:
    """Map each ticket id to its table row line in STATUS.md."""
    md = (_DOCS / "STATUS.md").read_text(encoding="utf-8")
    rows: dict[str, str] = {}
    for line in md.splitlines():
        match = re.match(r"\|\s*(T-\d+)\s*\|", line)
        if match:
            rows[match.group(1)] = line
    return rows


def test_every_yaml_status_value_is_known() -> None:
    statuses = set(_yaml_ticket_statuses().values())
    unknown = statuses - set(_STATUS_ICONS)
    assert not unknown, f"STATUS.yaml uses unknown status value(s): {unknown}"


def test_md_and_yaml_cover_the_same_tickets() -> None:
    yaml_ids = set(_yaml_ticket_statuses())
    md_ids = set(_md_ticket_rows())
    assert yaml_ids == md_ids, (
        f"only in YAML: {sorted(yaml_ids - md_ids)}; only in MD: {sorted(md_ids - yaml_ids)}"
    )


def test_md_status_icon_matches_yaml_status() -> None:
    rows = _md_ticket_rows()
    mismatches = [
        (tid, status, _STATUS_ICONS[status])
        for tid, status in _yaml_ticket_statuses().items()
        if _STATUS_ICONS[status] not in rows.get(tid, "")
    ]
    assert not mismatches, f"STATUS.md row missing the YAML status icon for: {mismatches}"
