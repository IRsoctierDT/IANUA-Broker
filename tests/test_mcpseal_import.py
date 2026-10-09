# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""mcpseal ``.mcp-lock.json`` import (R-LIVE-TOOL-DRIFT).

The hash vectors below are copied from mcpseal's published test vectors
(github.com/confuseddude/mcpseal, test-vectors/hash-fixtures.json, MIT license)
so CI keeps proving byte-for-byte compatibility with mcpseal 0.1.4's pin.
They are kept as ASCII-escaped JSON so no non-ASCII text sits in this source.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpscan import cli
from mcpscan.discovery.live_tools import mcpseal_pin
from mcpscan.drift import Direction, DriftCause, FactKind, PostureFact, Snapshot, diff_snapshots
from mcpscan.drift.mcpseal_import import LockfileImportError, parse_mcp_lock

MCPSEAL_VECTORS = [
    (
        (
            '{"name": "search_repositories", "description": "Search for GitHub repositories matching'
            ' a query", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},'
            ' "required": ["query"]}}'
        ),
        "ea7e14849d902b4d4e2ce89646518d56914efabdc243822cf305b12ec773ad8a",
    ),
    (
        (
            '{"name": "translate_text", "description": "\\u00dcbersetzt Text ins Deutsche \\u2014'
            ' \\u652f\\u6301\\u4e2d\\u6587 emoji \\ud83c\\udf0d and \\"quoted\\" text", "inputSchema":'
            ' {"type": "object", "properties": {"text": {"type": "string"}}}}'
        ),
        "708e9075dd915572f1b3cdbb5319edce11936c0b85c0f705ee6a555855fba690",
    ),
    (
        (
            '{"inputSchema": {"required": ["title"], "properties": {"body": {"type": "string"},'
            ' "title": {"type": "string"}}, "type": "object"}, "description": "Create a new GitHub'
            ' issue", "name": "create_issue"}'
        ),
        "4446c19fa5319093733684e8c731089768de19778368d01d2f5ca268850b1c6a",
    ),
]


@pytest.mark.parametrize(("tool_json", "expected"), MCPSEAL_VECTORS)
def test_pin_matches_mcpseal_published_vectors(tool_json: str, expected: str) -> None:
    tool = json.loads(tool_json)
    assert mcpseal_pin(tool["name"], tool["description"], tool["inputSchema"]) == expected


def _lock(**overrides: object) -> str:
    tool = json.loads(MCPSEAL_VECTORS[0][0])
    doc: dict[str, object] = {
        "version": 1,
        "generatedAt": "2026-10-09T00:00:00Z",
        "generatedBy": "mcpseal 0.1.4",
        "servers": {
            "github": {
                "transport": "stdio",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "commandHash": "sha256:" + "0" * 64,
                "tools": {
                    tool["name"]: {
                        "hash": "sha256:" + MCPSEAL_VECTORS[0][1],
                        "description": "PLAINTEXT-CANARY " + tool["description"],
                        "approvedAt": "2026-10-09T00:00:00Z",
                        "approvedBy": "IDRozenblad",
                        "status": "approved",
                    },
                    "delete_repo": {
                        "hash": "sha256:" + "1" * 64,
                        "description": "x",
                        "approvedAt": "",
                        "approvedBy": "",
                        "status": "denied",
                    },
                },
            }
        },
        "policy": {"onDrift": "block"},
        "signature": None,
    }
    doc.update(overrides)
    return json.dumps(doc)


def test_imports_approved_pins_only_and_never_the_description() -> None:
    loaded = parse_mcp_lock(_lock())
    tools = [f for f in loaded.facts if f.kind is FactKind.TOOL]
    assert [f.key for f in tools] == ["tool:stdio://github:search_repositories"]
    assert tools[0].detail_map()["mcpseal"] == MCPSEAL_VECTORS[0][1]
    assert tools[0].detail_map()["provenance"] == "mcpseal-import"
    assert any(f.kind is FactKind.SERVER and f.key == "server:stdio://github" for f in loaded.facts)
    assert "PLAINTEXT-CANARY" not in repr(loaded)
    assert any("not 'approved'" in w for w in loaded.warnings)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (_lock(version=2), "unsupported lockfile version"),
        (_lock(version="1"), "unsupported lockfile version"),
        (_lock(servers=[]), "'servers'"),
        ("[" * 200 + "]" * 200, "too deep"),
        ("not json", "not valid JSON"),
        ("[]", "not a JSON object"),
    ],
)
def test_bad_lockfiles_are_refused_whole(text: str, message: str) -> None:
    with pytest.raises(LockfileImportError, match=message):
        parse_mcp_lock(text)


def test_bad_entries_are_skipped_with_warnings() -> None:
    doc = json.loads(_lock())
    doc["servers"]["--evil"] = {"tools": {}}
    doc["servers"]["github"]["tools"]["search_repositories"]["hash"] = "md5:abc"
    loaded = parse_mcp_lock(json.dumps(doc))
    assert not [f for f in loaded.facts if f.kind is FactKind.TOOL]
    assert len(loaded.warnings) >= 2


def _current(pin: str) -> Snapshot:
    server = parse_mcp_lock(_lock()).facts[-1]  # the matching SERVER fact
    tool = PostureFact(
        kind=FactKind.TOOL,
        key="tool:stdio://github:search_repositories",
        summary="t",
        detail=(
            ("description", "d" * 64),
            ("digest", "e" * 64),
            ("mcpseal", pin),
            ("schema", "f" * 64),
            ("server", "stdio://github"),
        ),
    )
    return Snapshot(schema_version="1.0", facts=(server, tool))


def test_matching_live_tool_diffs_clean_against_imported_pin() -> None:
    baseline = Snapshot(schema_version="1.0", facts=parse_mcp_lock(_lock()).facts)
    assert diff_snapshots(baseline, _current(MCPSEAL_VECTORS[0][1])).entries == ()


def test_changed_tool_is_a_pin_regression() -> None:
    baseline = Snapshot(schema_version="1.0", facts=parse_mcp_lock(_lock()).facts)
    (entry,) = diff_snapshots(baseline, _current("9" * 64)).entries
    assert entry.direction is Direction.REGRESSION
    assert entry.cause is DriftCause.TOOL_PIN_CHANGED


def test_cli_baseline_imports_and_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = tmp_path / ".mcp-lock.json"
    lock.write_text(_lock(), encoding="utf-8")
    out = tmp_path / "base.json"
    assert (
        cli.main(
            [
                "baseline",
                "--root",
                str(tmp_path),
                "--no-inventory",
                "--out",
                str(out),
                "--import-mcp-lock",
                str(lock),
            ]
        )
        == 0
    )
    text = out.read_text(encoding="utf-8")
    assert "mcpseal-import" in text and "PLAINTEXT-CANARY" not in text
    assert "imported 1 mcpseal tool pin" in capsys.readouterr().err
    lock.write_text(_lock(version=99), encoding="utf-8")
    assert (
        cli.main(
            [
                "baseline",
                "--root",
                str(tmp_path),
                "--no-inventory",
                "--out",
                str(out),
                "--import-mcp-lock",
                str(lock),
            ]
        )
        == 2
    )
    assert "unsupported lockfile version" in capsys.readouterr().err
