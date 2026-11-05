# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Guard: every action a workflow runs is pinned to an immutable commit.

A tag or branch (``@v7``, ``@release/v1``) is a mutable pointer: whoever controls
the upstream repository, or compromises it, can move it, and the next run then
executes the new code with this repository's token, secrets and PyPI publishing
identity. A full 40-character commit SHA cannot be moved. Each pin carries a
``# vX.Y.Z`` comment naming the release it is, so a reviewer can read it and
Dependabot can keep it current.

Local actions (``./path``) are part of this repository and need no pin; a Docker
action must be pinned by image digest. A new or edited workflow that references
an action by tag or branch fails this test on every OS/Python cell.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"

_SHA_PIN = re.compile(r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}")
_DIGEST_PIN = re.compile(r"docker://[^@\s]+@sha256:[0-9a-f]{64}")
# A ``uses:`` key on a live YAML line; a commented-out example (``#   uses: …``)
# does not match because ``#`` precedes the key.
_USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)\s*(?:#\s*(?P<comment>\S+))?\s*$")
_RELEASE_COMMENT = re.compile(r"v\d+\.\d+\.\d+")


def _is_pinned(ref: str) -> bool:
    return (
        ref.startswith("./")
        or _SHA_PIN.fullmatch(ref) is not None
        or _DIGEST_PIN.fullmatch(ref) is not None
    )


def _uses_values(node: Any) -> list[str]:
    """Every ``uses:`` value in a parsed workflow: steps and reusable-workflow jobs."""
    if isinstance(node, dict):
        found: list[str] = []
        for key, value in node.items():
            if key == "uses" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_uses_values(value))
        return found
    if isinstance(node, list):
        return [ref for item in node for ref in _uses_values(item)]
    return []


def _workflows() -> list[Path]:
    return sorted(p for p in _WORKFLOW_DIR.iterdir() if p.suffix in {".yml", ".yaml"})


def test_workflows_are_found() -> None:
    # Fail closed: if the directory moved, the guards below must not pass vacuously.
    assert _workflows(), f"no workflows under {_WORKFLOW_DIR}"


@pytest.mark.parametrize("workflow", _workflows(), ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(workflow: Path) -> None:
    refs = _uses_values(yaml.safe_load(workflow.read_text(encoding="utf-8")))
    unpinned = [ref for ref in refs if not _is_pinned(ref)]
    assert not unpinned, (
        f"{workflow.name}: pin these to a full commit SHA with a '# vX.Y.Z' comment "
        f"(see docs/DEVSECOPS.md §7): {unpinned}"
    )


@pytest.mark.parametrize("workflow", _workflows(), ids=lambda p: p.name)
def test_every_pin_names_its_release(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    lines = [m for m in map(_USES_LINE.match, text.splitlines()) if m]
    # The line scan must see exactly what the YAML parser sees, or a flow-style
    # ``uses`` could slip past the comment check below.
    assert sorted(m["ref"] for m in lines) == sorted(_uses_values(yaml.safe_load(text)))
    unnamed = [
        m["ref"]
        for m in lines
        if _SHA_PIN.fullmatch(m["ref"])
        and not (m["comment"] and _RELEASE_COMMENT.fullmatch(m["comment"]))
    ]
    assert not unnamed, f"{workflow.name}: add a '# vX.Y.Z' release comment to: {unnamed}"


@pytest.mark.parametrize(
    "ref",
    [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370",
        "octo-org/shared/.github/workflows/ci.yml@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "./.github/actions/local",
        "docker://ghcr.io/org/image@sha256:" + "a" * 64,
    ],
)
def test_immutable_refs_are_accepted(ref: str) -> None:
    assert _is_pinned(ref)


@pytest.mark.parametrize(
    "ref",
    [
        "actions/checkout@v7",  # tag: can be moved upstream
        "actions/checkout@v7.0.1",  # exact tag is still mutable
        "pypa/gh-action-pypi-publish@release/v1",  # branch
        "actions/checkout@main",
        "actions/checkout@3d3c42e",  # short SHA: ambiguous, resolvable as a ref
        "actions/checkout@3D3C42E5AAC5BA805825DA76410C181273BA90B1",  # not a git object name
        "actions/checkout",  # no ref at all
        "docker://alpine:3.20",  # image tag: mutable
        "docker://ghcr.io/org/image@sha256:abc",  # truncated digest
    ],
)
def test_mutable_refs_are_rejected(ref: str) -> None:
    assert not _is_pinned(ref)


def test_scan_reads_steps_and_reusable_jobs_but_not_comments() -> None:
    workflow = """\
jobs:
  build:
    steps:
      - uses: actions/checkout@v7
      # - uses: actions/setup-example@v1
      - run: echo hi
  call:
    uses: octo-org/shared/.github/workflows/ci.yml@main
"""
    parsed = yaml.safe_load(workflow)
    assert _uses_values(parsed) == [
        "actions/checkout@v7",
        "octo-org/shared/.github/workflows/ci.yml@main",
    ]
    scanned = [m["ref"] for m in map(_USES_LINE.match, workflow.splitlines()) if m]
    assert sorted(scanned) == sorted(_uses_values(parsed))
