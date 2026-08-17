# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Report renderers: terminal, JSON, self-contained HTML, and SARIF 2.1.0.

All renderers consume only the pure ``domain`` model. Secrets are already
fingerprinted before a Report exists (R1), so no renderer can leak a raw value.
``RenderOptions`` controls path privacy (FR-R7) and secret reveal (FR-R4).

Report integrity: the strings a report interpolates — server names, argument
values, config paths — come from files the scanner does not own (a ``.mcp.json``
inside a cloned repo is attacker-authored). :func:`inert_text` is the boundary
that makes such a string safe to print; see its docstring.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..checks.tool_integrity import HIDDEN_CODEPOINTS
from ..domain import Severity

_SEPARATORS = ("/", "\\")

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class RenderOptions:
    """Cross-renderer display options."""

    show_secrets: bool = False
    absolute_paths: bool = False
    home: str | None = None


def inert_text(text: str) -> str:
    """Return ``text`` with every character a terminal would *act on* defanged.

    Findings quote strings the scanner does not control: a server name, an
    argument, an ``.env`` key, a config path. A hostile ``.mcp.json`` — the one
    inside a repo you just cloned — can therefore choose what the report prints.
    Left raw, that is a report-forgery primitive:

    - an ANSI/CSI sequence (``\\x1b[2J``, cursor moves, color) can erase the scan
      output above it or repaint a CRITICAL line as a clean one;
    - a newline or carriage return can forge whole report lines — a fabricated
      ``▶ server [grade A]`` header the operator has no way to distinguish;
    - a bidi override or zero-width joiner can visually reorder or hide part of
      the very value the tool is warning about (the same primitive
      ``TOOL-HIDDEN-UNICODE`` exists to flag).

    Each such character is replaced by its visible ``\\uXXXX`` escape rather than
    dropped: a security tool must show that something was there. Ordinary text —
    including non-Latin scripts and emoji — is returned unchanged.

    This is the terminal-side counterpart of :func:`mcpscan.lan.sanitize.sanitize_remote`
    (remote bytes) and is applied by every renderer that writes to a terminal.
    The JSON/SARIF renderers need no equivalent: ``json.dumps`` already escapes
    control characters, and the HTML renderer escapes its own markup.
    """
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F or code in HIDDEN_CODEPOINTS:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def display_path(path: str, opts: RenderOptions) -> str:
    """Relativize a filesystem path under the home dir to ``~/…`` (FR-R7).

    Non-path locations (e.g. ``ip:port``) and paths outside home are returned
    unchanged. ``--absolute-paths`` disables relativization.
    """
    if opts.absolute_paths or not opts.home:
        return path
    # Separator-agnostic so it works regardless of the OS the report is rendered
    # on (Windows CI rendering POSIX-style paths, and vice versa).
    home = opts.home.rstrip("/\\")
    if path == home:
        return "~"
    if any(path.startswith(home + s) for s in _SEPARATORS):
        return "~" + path[len(home) :]
    return path
