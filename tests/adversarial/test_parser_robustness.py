# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Objective A — crash the scanner with the file it is asked to read.

Every parser in the tool sits behind a promise: *malformed input becomes a
finding, never an exception* (SPEC NFR-S3; the ``HostAdapter.parse`` contract).
A parser that breaks that promise is a denial of service on a security control —
the scan dies, CI goes red for the wrong reason, and the operator learns nothing
about the posture the scan was supposed to measure.

The battery attacks each parser with the shapes a fuzzer finds first, plus the
one shape a size cap cannot stop: **deep nesting**. ``json.loads`` raises
``RecursionError`` there, which is a ``RuntimeError`` — so an ``except
ValueError`` that looks exhaustive is not, and 400 KB of ``[[[[…]]]]`` under a
5 MB cap crashes the run.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from adversarial.corpus import (
    KITCHEN_SINK,
    deep_json,
    deep_object_json,
    hostile_config,
)
from mcpscan.acceptance import parse_ledger
from mcpscan.adapters.base import HostAdapter, ParsedConfig
from mcpscan.adapters.claude import ClaudeAdapter
from mcpscan.adapters.cline import ClineAdapter
from mcpscan.adapters.continue_ import ContinueAdapter
from mcpscan.adapters.cursor import CursorAdapter
from mcpscan.adapters.vscode import VSCodeAdapter
from mcpscan.adapters.windsurf import WindsurfAdapter
from mcpscan.adapters.zed import ZedAdapter
from mcpscan.checks import parse_env_text
from mcpscan.checks.broker import BrokerParseError, parse_broker_manifest
from mcpscan.checks.token_store import decode_jwt_unverified, decode_store
from mcpscan.datapack import DataPackError, parse_datapack
from mcpscan.drift.baseline import BaselineError, baseline_created_at, load_baseline
from mcpscan.fix import plan_config_fixes
from mcpscan.lan.manifest import ManifestError, load_manifest
from mcpscan.lan.policy import PolicyError, load_policy

ADAPTERS: tuple[HostAdapter, ...] = (
    ClaudeAdapter(),
    CursorAdapter(),
    WindsurfAdapter(),
    ClineAdapter(),
    VSCodeAdapter(),
    ZedAdapter(),
    ContinueAdapter(),
)

#: Malformed documents that must each degrade to ``parse_error``, not an
#: exception. Ordered roughly by how far past a naive parser they get.
MALFORMED: tuple[str, ...] = (
    "",  # empty file
    "   \n\t  ",  # whitespace only
    "{not json",  # truncated object
    "[1, 2, 3]",  # valid JSON, wrong root type
    '"just a string"',
    "null",
    "true",
    "123",
    "\x00\x01\x02",  # binary garbage (what a replaced-bytes read yields)
    "﻿{}",  # UTF-8 BOM before the document
    '{"mcpServers": []}',  # right key, wrong container type
    '{"mcpServers": {"a": "not-an-object"}}',
    '{"mcpServers": {"a": {"command": {"nested": "object"}}}}',
    '{"mcpServers": {"a": {"args": "not-a-list", "env": "not-a-map"}}}',
    '{"mcpServers": null}',
    '{"permissions": {"allow": "not-a-list"}}',
    "{" * 500 + "}" * 500,  # deep, but shallow enough to parse
    '{"a": 1e999999}',  # overflows to inf
    '{"a": ' + "9" * 5000 + "}",  # int-to-str conversion limit
    KITCHEN_SINK,
)


# Payloads are passed as *factories*, never as values, and every parametrization
# over them carries an explicit id. A 400 KB string used as a parameter becomes a
# 400 KB pytest node id: it is reported, matched, and written out on every line
# that names the test. That turned a 10-second suite into an 18-minute one on
# Windows CI and errored the run outright — a battery about hostile input should
# not be a denial of service on its own test runner.
HOSTILE_DOCUMENTS: tuple[Callable[[], str], ...] = (
    *[(lambda text=text: text) for text in MALFORMED],
    deep_json,
    deep_object_json,
)
DOCUMENT_IDS: tuple[str, ...] = (
    # Short but self-describing: a failure names the payload, not an index.
    *[repr(text[:24]) for text in MALFORMED],
    "deep-array",
    "deep-object",
)


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.name)
@pytest.mark.parametrize("raw", MALFORMED, ids=lambda s: repr(s[:24]))
def test_adapter_never_raises_on_malformed_config(adapter: HostAdapter, raw: str) -> None:
    """Every host adapter degrades malformed input to a ParsedConfig."""
    cfg = adapter.parse("/cfg", raw)
    assert isinstance(cfg, ParsedConfig)
    # Either it parsed to something usable, or it said why it could not.
    assert cfg.parse_error is not None or isinstance(cfg.servers, tuple)


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.name)
@pytest.mark.parametrize("depth_payload", [deep_json, deep_object_json], ids=["array", "object"])
def test_adapter_survives_deeply_nested_config(
    adapter: HostAdapter, depth_payload: Callable[[], str]
) -> None:
    """Deep nesting is a parse error, not a RecursionError escaping the adapter.

    This is the regression guard for the whole class: the payload is ~400 KB —
    comfortably inside the 5 MB ``io_safe`` cap — so nothing upstream can stop
    it, and ``RecursionError`` is not a ``ValueError``.
    """
    cfg = adapter.parse("/cfg", depth_payload())
    assert cfg.parse_error is not None
    assert cfg.servers == ()


@pytest.mark.parametrize(
    ("name", "parse"),
    [
        ("broker manifest", lambda raw: parse_broker_manifest(raw)),
        ("datapack", lambda raw: parse_datapack(raw)),
        ("acceptance ledger", lambda raw: parse_ledger(raw, "src")),
        ("token store", lambda raw: decode_store(raw)),
        ("baseline created_at", lambda raw: baseline_created_at(raw)),
        ("fix planner", lambda raw: plan_config_fixes("/cfg", raw)),
        ("lan manifest", lambda raw: load_manifest(raw.encode())),
        ("lan policy", lambda raw: load_policy(raw.encode())),
    ],
)
@pytest.mark.parametrize("make_raw", HOSTILE_DOCUMENTS, ids=DOCUMENT_IDS)
def test_total_parsers_never_raise(
    name: str, parse: Callable[[str], object], make_raw: Callable[[], str]
) -> None:
    """Parsers whose contract is "returns an error object" must never raise.

    These are the fail-closed boundaries: each returns a typed error rather than
    raising, so a caller that only catches its own error type stays correct.
    """
    parse(make_raw())  # the assertion IS "this does not raise"


@pytest.mark.parametrize("make_raw", HOSTILE_DOCUMENTS, ids=DOCUMENT_IDS)
def test_baseline_load_refuses_without_crashing(make_raw: Callable[[], str]) -> None:
    """``load_baseline`` is the one parser that raises — but only ``BaselineError``.

    A tampered baseline in CI must produce the typed refusal every caller
    handles, never an unhandled ``RecursionError`` that aborts the diff.
    """
    with pytest.raises(BaselineError):
        load_baseline(make_raw())


def test_error_objects_are_the_documented_types() -> None:
    """The fail-closed refusals are typed, so callers can branch on them."""
    assert isinstance(parse_broker_manifest(deep_json()), BrokerParseError)
    assert isinstance(parse_datapack(deep_json()), DataPackError)
    assert isinstance(load_manifest(deep_json().encode()), ManifestError)
    assert isinstance(load_policy(deep_json().encode()), PolicyError)
    assert decode_store(deep_json()) is None
    assert baseline_created_at(deep_json()) is None
    assert parse_ledger(deep_json(), "src").entries == ()


# --- JSONC: the comment stripper is a parser of its own ----------------------
# VS Code and Zed configs allow comments and trailing commas, so the tool
# hand-rolls a stripper. A stripper that is not string-aware is a parser
# differential: the editor and the scanner would disagree about what the config
# says, and the attacker picks which one is wrong.
JSONC_DIFFERENTIALS: tuple[tuple[str, object], ...] = (
    # A "//" inside a string value is data, not a comment.
    ('{"url": "http://example.test/mcp"}', {"url": "http://example.test/mcp"}),
    # A "/*" inside a string value likewise.
    ('{"glob": "src/*"}', {"glob": "src/*"}),
    ('{"a": "/* not a comment */"}', {"a": "/* not a comment */"}),
    # An apostrophe in a value must not open a "string" the stripper then
    # follows past the real closing quote.
    ('{"a": "it\'s fine", "b": 1}', {"a": "it's fine", "b": 1}),
    ('{"a": 1} // don\'t worry\n', {"a": 1}),
    ('{ /* don\'t */ "a": 1 }', {"a": 1}),
    # An escaped quote must not end the string early.
    (r'{"a": "b\"//c"}', {"a": 'b"//c'}),
    (r'{"a": "trailing backslash \\"}', {"a": "trailing backslash \\"}),
    # A comma-brace pair inside a string is not a trailing comma.
    ('{"a": "x,}"}', {"a": "x,}"}),
    ('{"a": "y,]"}', {"a": "y,]"}),
    # Genuine JSONC features still work.
    ('{"a": 1,}', {"a": 1}),
    ('// lead\n{"a": [1, 2,],}', {"a": [1, 2]}),
    ('{"a": 1} /* unterminated', {"a": 1}),
)


@pytest.mark.parametrize(("raw", "expected"), JSONC_DIFFERENTIALS, ids=lambda v: repr(v)[:28])
def test_jsonc_stripper_is_string_aware(raw: str, expected: object) -> None:
    """The comment/trailing-comma stripper never edits inside a JSON string.

    Each case is a spot where a naive stripper corrupts the document — and a
    corrupted document is either a crash or, worse, a *silently different* one.
    """
    from mcpscan.adapters.jsonc import loads_jsonc

    assert loads_jsonc(raw) == expected


def test_vscode_and_zed_agree_with_stdlib_on_plain_json() -> None:
    """JSONC parsing of comment-free JSON matches the stdlib exactly.

    Guards the differential directly: for a document with no JSONC features,
    the hand-rolled path must not change meaning.
    """
    from mcpscan.adapters.jsonc import loads_jsonc

    raw = hostile_config()
    assert loads_jsonc(raw) == json.loads(raw)


# --- .env parsing ------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "",
        "no-equals-here",
        "=value-without-key",
        "KEY=",
        "KEY=value=with=equals",
        "  KEY  =  value  ",
        "#comment=notakey",
        "KEY='single'\nKEY2=\"double\"",
        "\x00\x01=\x02",
        KITCHEN_SINK,
        "\n".join(f"K{i}=v{i}" for i in range(10_000)),
    ],
    ids=lambda s: repr(s[:24]),
)
def test_env_parsing_is_total(text: str) -> None:
    """``.env`` parsing never raises and always yields well-formed entries."""
    parsed = parse_env_text("/p/.env", text)
    assert all(isinstance(n, int) and n >= 1 for n, _, _ in parsed.entries)
    assert all(isinstance(k, str) and isinstance(v, str) for _, k, v in parsed.entries)


# --- JWT decode --------------------------------------------------------------
@pytest.mark.parametrize(
    "token",
    [
        "",
        "a.b",
        "a.b.c.d",
        "..",
        "a..c",
        "not-base64.not-base64.not-base64",
        "eyJ0eXAiOiJKV1QifQ." + "!" * 20 + ".sig",  # invalid base64 payload
        "e30.e30.e30",  # valid base64, payload is {} not a claims object
        "e30." + "A" * 100_000 + ".e30",  # oversized segment
        KITCHEN_SINK,
    ],
    ids=lambda s: repr(s[:24]),
)
def test_jwt_decode_is_total(token: str) -> None:
    """An opaque or hostile token decodes to ``None``, never an exception.

    The decode is unverified by design (it only reads ``exp``/``scope``), which
    makes its input fully attacker-chosen whenever a token store is inspected.
    """
    assert decode_jwt_unverified(token) is None or decode_jwt_unverified(token) is not None


def test_engine_survives_a_hostile_project_root(tmp_path: Path) -> None:
    """The full pipeline over a directory of hostile configs completes."""
    from mcpscan.engine import scan

    (tmp_path / ".mcp.json").write_text(deep_json(), encoding="utf-8")
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text("{not json", encoding="utf-8")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(hostile_config(), encoding="utf-8")
    (tmp_path / ".env").write_text(KITCHEN_SINK, encoding="utf-8")

    report = scan(
        roots=[tmp_path], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False
    )
    assert report.schema_version
    # The two unparseable configs are reported rather than silently dropped.
    ids = [f.id for s in report.servers for f in s.findings]
    assert ids.count("CONFIG-UNREADABLE") == 2
