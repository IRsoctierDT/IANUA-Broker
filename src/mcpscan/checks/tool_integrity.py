# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Tool-integrity checks: static tool-poisoning heuristics (Wave 3 Feature T).

Scans the string surfaces a host config actually carries — a server's ``args``,
its ``env`` VALUES, and its ``name`` — for **high-confidence** tampering signals
that a human reviewer would miss but an agent would act on:

- invisible / bidirectional Unicode control characters (zero-width joiners,
  RTL/LTR overrides, a stray BOM) that hide text from a reader while the model
  still reads it → ``TOOL-HIDDEN-UNICODE``;
- a small curated set of prompt-injection phrases embedded in a config value →
  ``TOOL-INJECTION-TEXT``.

Deliberately narrow: only an *actual* invisible control character or an *exact*
curated phrase fires, so ordinary text never trips a false positive. Pure over
its inputs and runs in the normal scan — no new I/O, no clock, no network. Raw
surface values (which may hold secrets) never reach a finding; only the char
codepoints or the matched curated phrase are named.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..adapters.base import ServerDecl
from ..domain import Dimension, Finding, Location, Severity

# Zero-width and bidirectional Unicode control characters. These render as
# nothing (or reorder surrounding text) for a human but are ordinary codepoints
# to a model reading the config — the classic "hidden instruction" primitive.
# Curated to high-confidence controls only so legitimate text never matches.
#
# Public because this is the tool's single catalog of "invisible to a reader":
# ``report.inert_text`` neutralizes exactly these codepoints on the way out to a
# terminal and ``lan.sanitize`` strips them from remote responses, so what the
# scanner *flags* as hidden and what it *renders* can never drift apart.
HIDDEN_CODEPOINTS: frozenset[int] = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    }
)

# Exact prompt-injection phrases (matched case-insensitively as substrings). Kept
# short and unambiguous — each is a phrase a benign MCP config value would not
# carry, so a hit is high-confidence tampering, not ordinary prose.
_INJECTION_PHRASES: tuple[str, ...] = (
    "ignore previous instructions",
    "disregard the above",
    "you are now",
    "system prompt:",
    "<system>",
)


def hidden_unicode_codepoints(text: str) -> tuple[int, ...]:
    """Sorted, de-duplicated invisible/bidi control codepoints present in ``text``."""
    return tuple(sorted({ord(ch) for ch in text if ord(ch) in HIDDEN_CODEPOINTS}))


def injection_phrase(text: str) -> str | None:
    """The first curated prompt-injection phrase in ``text`` (case-insensitive), or None."""
    lowered = text.lower()
    for phrase in _INJECTION_PHRASES:
        if phrase in lowered:
            return phrase
    return None


def _surfaces(server: ServerDecl) -> Iterator[tuple[str, str]]:
    """Yield ``(surface_label, text)`` for every string the config carries.

    The label names the surface for a reader **without** quoting the raw value,
    which may be a secret; only the server name and env *keys* (never secret) are
    named literally.
    """
    yield ("the server name", server.name)
    for arg in server.args:
        yield ("an argument", arg)
    for key, value in server.env:
        yield (f"env value {key!r}", value)


def _hidden_unicode_finding(
    server_name: str, surface: str, codepoints: tuple[int, ...], config_path: str
) -> Finding:
    codes = ", ".join(f"U+{cp:04X}" for cp in codepoints)
    return Finding(
        id="TOOL-HIDDEN-UNICODE",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.MEDIUM,
        title=f"Server {server_name!r}: hidden Unicode control characters in {surface}",
        location=Location(path=config_path),
        remediation=(
            "Remove the invisible/bidirectional control characters. If the value is "
            "legitimate, re-enter it as plain, visible text."
        ),
        rationale=(
            f"Zero-width or bidirectional Unicode control characters ({codes}) can hide "
            "instructions from a human reviewer while an agent still reads them — a "
            "tool-poisoning primitive."
        ),
    )


def _injection_finding(server_name: str, surface: str, phrase: str, config_path: str) -> Finding:
    return Finding(
        id="TOOL-INJECTION-TEXT",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.MEDIUM,
        title=f"Server {server_name!r}: prompt-injection phrase in {surface}",
        location=Location(path=config_path),
        remediation=(
            "Remove the injected instruction text from the configuration value; a tool's "
            "metadata should describe the tool, not command the agent."
        ),
        rationale=(
            f'The configuration carries the prompt-injection phrase "{phrase}" in {surface}, '
            "which can hijack an agent that reads the tool metadata."
        ),
    )


def check_tool_integrity(server: ServerDecl, config_path: str) -> list[Finding]:
    """Flag hidden-Unicode and prompt-injection tampering in a server's config strings.

    High-confidence only: a finding fires solely on an actual invisible control
    character or an exact curated injection phrase, so clean configs stay silent.
    """
    findings: list[Finding] = []
    for surface, text in _surfaces(server):
        codepoints = hidden_unicode_codepoints(text)
        if codepoints:
            findings.append(_hidden_unicode_finding(server.name, surface, codepoints, config_path))
        phrase = injection_phrase(text)
        if phrase is not None:
            findings.append(_injection_finding(server.name, surface, phrase, config_path))
    return findings
