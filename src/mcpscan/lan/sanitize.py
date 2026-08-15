# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Hostile-by-default handling of remote responses (LAN proposal §3.5).

Every byte a remote host returns is untrusted adversarial input — MCP research
flags prompt injection, tool poisoning, and capability misrepresentation. Nothing
remote reaches a report or (especially) an LLM/agent context raw. This module
normalizes any remote string to an inert, clearly-labelled form: ANSI/control
sequences stripped, non-UTF-8 replaced, whitespace collapsed, length-capped, and
prefixed so it can never be mistaken for tool output or an instruction.
"""

from __future__ import annotations

import re

from ..checks.tool_integrity import HIDDEN_CODEPOINTS

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_LABEL = "[untrusted remote data]"


def sanitize_remote(raw: bytes | str, *, max_len: int = 200) -> str:
    """Return an inert, labelled, length-capped rendering of remote bytes.

    A prompt-injection payload survives only as plain, labelled text — it is
    never interpreted, interpolated into remediation prose, or fed to a model.
    """
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = _ANSI.sub("", text)
    # Replace C0/C1 control characters and DEL with a space, keep printable text.
    # The C1 block (U+0080–U+009F) matters as much as C0: U+009B is the 8-bit
    # form of CSI, which a UTF-8 terminal still acts on, so a ``ch >= " "`` test
    # alone would let a remote host keep its escape sequences.
    text = "".join(
        ch if (ch >= " " and ch != "\x7f" and not ("\x80" <= ch <= "\x9f")) else " " for ch in text
    )
    # Zero-width and bidirectional controls are *printable* by the test above but
    # are exactly the "invisible to a reader" primitive the scanner flags in
    # configs (``TOOL-HIDDEN-UNICODE``). A remote banner must not be able to
    # reorder or hide the text of the very finding that quotes it, so the same
    # catalog is stripped here — "inert" has to mean inert on both channels.
    text = "".join(" " if ord(ch) in HIDDEN_CODEPOINTS else ch for ch in text)
    text = " ".join(text.split())  # collapse runs of whitespace
    if not text:
        return f"{_LABEL} (empty)"
    if len(text) > max_len:
        text = text[:max_len] + "…"
    return f"{_LABEL} {text}"
