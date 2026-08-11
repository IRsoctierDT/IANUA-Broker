# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the JSONC (JSON-with-comments) helper."""

from __future__ import annotations

import pytest

from mcpscan.adapters.jsonc import loads_jsonc, strip_jsonc


def test_line_comment_is_stripped() -> None:
    assert loads_jsonc('{"a": 1 // trailing note\n}') == {"a": 1}


def test_block_comment_is_stripped() -> None:
    assert loads_jsonc('{/* header */ "a": 1}') == {"a": 1}


def test_trailing_comma_in_object_and_array() -> None:
    assert loads_jsonc('{"a": [1, 2,], "b": 2,}') == {"a": [1, 2], "b": 2}


def test_comment_like_text_inside_string_is_preserved() -> None:
    # The load-bearing case: // and /* */ inside a string value must survive.
    data = loads_jsonc('{"url": "http://example.com/mcp", "note": "a /* b */ c"}')
    assert data == {"url": "http://example.com/mcp", "note": "a /* b */ c"}


def test_comma_brace_inside_string_is_not_treated_as_trailing() -> None:
    # ",]" and ",}" inside a string must not be mangled by trailing-comma removal.
    data = loads_jsonc('{"a": "x,]", "b": "y,}"}')
    assert data == {"a": "x,]", "b": "y,}"}


def test_escaped_quote_in_string_is_handled() -> None:
    data = loads_jsonc(r'{"a": "she said \"hi\" // not a comment"}')
    assert data == {"a": 'she said "hi" // not a comment'}


def test_plain_json_is_unchanged() -> None:
    raw = '{"servers": {"s": {"command": "npx"}}}'
    assert loads_jsonc(raw) == {"servers": {"s": {"command": "npx"}}}


def test_malformed_still_raises() -> None:
    import json

    with pytest.raises(json.JSONDecodeError):
        loads_jsonc("{not json")


def test_strip_jsonc_leaves_valid_json() -> None:
    out = strip_jsonc('{\n  "a": 1, // c\n  "b": [2,],\n}')
    import json

    assert json.loads(out) == {"a": 1, "b": [2]}
