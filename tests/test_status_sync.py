# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Guard: the status docs must stay in sync with each other and with the release.

STATUS.yaml is the source of truth; STATUS.md is a hand-maintained view. These
tests fail if the two drift on ticket coverage or status, so the Markdown can't
silently fall behind the YAML.

Cross-file parity alone is not enough: both files can go stale together while
still agreeing, which is how the tracker sat at v1.6.0 through five releases.
The release guard below anchors them to pyproject.toml, so a release-please
version bump fails the suite until the tracker is refreshed with it
(docs/ROADMAP.md, R-STATUS-SYNC).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_DOCS = _ROOT / "docs"

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


def _package_version() -> str:
    """The distribution version release-please bumps, from pyproject.toml."""
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _yaml_meta() -> dict[str, object]:
    data = yaml.safe_load((_DOCS / "STATUS.yaml").read_text(encoding="utf-8"))
    return dict(data["meta"])


def test_yaml_release_matches_package_version() -> None:
    """STATUS.yaml must name the version it describes, and name the current one."""
    release = _yaml_meta().get("release")
    assert release, "STATUS.yaml is missing meta.release"
    assert release == _package_version(), (
        f"STATUS.yaml meta.release is {release!r} but pyproject.toml is at "
        f"{_package_version()!r}; refresh the tracker (docs/STATUS.yaml and the "
        f"docs/STATUS.md view) for the current release"
    )


def test_md_release_matches_yaml_release() -> None:
    """The Markdown view's Released bullet must carry the same version."""
    md = (_DOCS / "STATUS.md").read_text(encoding="utf-8")
    match = re.search(r"^- \*\*Released:\*\* (\S+)", md, re.MULTILINE)
    assert match, "STATUS.md is missing its '- **Released:** <version>' bullet"
    assert match.group(1) == _yaml_meta()["release"], (
        f"STATUS.md says released {match.group(1)!r} but STATUS.yaml meta.release "
        f"is {_yaml_meta()['release']!r}"
    )
