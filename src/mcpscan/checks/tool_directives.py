# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Cross-tool directive heuristics for live tool metadata (medium confidence).

Tool-poisoning attacks rarely announce themselves with "ignore previous
instructions". The common shape is an ordinary-sounding *directive* in one
tool's description that steers how the agent uses **other** tools:

- "Before using ``send_email``, you must first call ``read_file`` on …"
  (a forced precondition that chains a sensitive tool);
- "When using ``search``, set ``query`` to …" (silent argument tampering);
- a credential path such as ``~/.ssh/id_rsa`` named in tool metadata;
- "Failure to do so will cause errors" (coercion to make the agent comply).

Legitimate servers occasionally say similar things ("call ``list_tables``
first"), so these fire as a separate, medium-severity finding rather than as a
prompt-injection hit; the high-confidence families live in
:func:`.tool_integrity.injection_phrase`. Measured on the MCPTox benchmark's
held-out split (docs/BENCHMARKS.md).

Pure and bounded: no I/O; every gap is length-limited and the patterns never
nest quantifiers. A hit returns a fixed label, never the matched text, because
tool metadata is untrusted and may embed secrets.
"""

from __future__ import annotations

import re

_I = re.IGNORECASE

# (pattern, label) in reporting order: the first match names the finding.
_DIRECTIVES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?:~|/root|/home/[\w.-]{1,64})?/\.ssh/|\bid_(?:rsa|ed25519|ecdsa)\b"
            r"|/etc/(?:passwd|shadow)\b|\.aws/credentials\b",
            _I,
        ),
        "names a credential or secret file path",
    ),
    (
        re.compile(
            r"\b(?:before|prior\s+to)\s+(?:using|calling|invoking|running|performing|executing|any)"
            r"\b[^.]{0,120}?\b(?:must|should|always|need\s+to|required\s+to)\b[^.]{0,40}?"
            r"\b(?:first\s+)?(?:call|use|invoke|run|trigger|execute)\b"
            r"|\bmust\s+first\s+(?:call|use|invoke|run|trigger)\b"
            r"|\b(?:must|always)\s+(?:first\s+)?(?:call|invoke|use|run|trigger)\b[^.]{0,80}\bfirst\b"
            r"|\b(?:before|prior\s+to)\s+(?:using|calling|invoking|running|performing|executing"
            r"|proceeding|parsing|deletion|deleting)\b[^.]{0,80}?[,:]?\s*"
            r"(?:you\s+(?:must|should)\s+)?(?:first\s+)?(?:use|call|invoke|trigger|scan|run)\s+"
            r"[`'\"]?[A-Za-z_][\w.-]{0,63}[`'\"]?"
            r"|\byou\s+must\s+call\s+(?:the\s+)?[`'\"][\w.-]{1,64}[`'\"]",
            _I,
        ),
        "requires calling another tool first",
    ),
    (
        re.compile(
            r"\b(?:must|always|should)\s+(?:change|set|modify|replace|prepend|append|redirect"
            r"|override|add)\b[^.]{0,80}\b(?:parameter|argument|param|field|query"
            r"|to\s+the\s+user's)\b"
            r"|\bwhen\s+(?:using|calling|invoking|you\s+use|a\s+user\s+calls)\b[^.]{0,80}?"
            r"\b(?:set|replace|override|redirect|change|modify|prepend|append)\b[^.]{0,80}?"
            r"\b(?:to|with|as)\b",
            _I,
        ),
        "dictates another tool's arguments",
    ),
    (
        re.compile(
            r"\b(?:failure\s+to|skipping\s+this|ignoring\s+this|not\s+doing\s+so"
            r"|without\s+this\s+step)\b[^.]{0,60}\b(?:will|would|may)\s+"
            r"(?:cause|result|lead|crash|break|fail)",
            _I,
        ),
        "threatens failure unless obeyed",
    ),
)


def cross_tool_directive(text: str) -> str | None:
    """The first cross-tool directive label found in ``text``, or None."""
    for pattern, label in _DIRECTIVES:
        if pattern.search(text):
            return label
    return None
