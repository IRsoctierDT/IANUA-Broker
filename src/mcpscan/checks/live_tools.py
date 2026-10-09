# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Live tool-manifest checks over a captured ``tools/list`` (R-LIVE-TOOLS).

Config-level tool-integrity checks (:mod:`.tool_integrity`) only see what a host
config *declares*. These checks see what the running server actually *tells the
model*: every tool's name, description, input/output schema strings and
annotation strings — the surface description-poisoning and rug-pull attacks
live in.

Detection reuses the tool-integrity catalogs (one source of truth for "invisible
to a reader" and for the curated injection phrases), so live and static checks
can never disagree on what counts as hidden or injected. Pure over a
:class:`~mcpscan.discovery.live_tools.LiveManifest`: no I/O, no clock, no network.

Redaction: tool descriptions are untrusted and may embed anything, including
secrets. A finding names only the tool (via ``repr``, which escapes control and
invisible characters), the surface label, codepoints, or the curated phrase —
never the raw description text.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence

from ..discovery.live_tools import MAX_DESCRIPTION_CHARS, LiveManifest, LiveTool
from ..domain import Dimension, Finding, Location, Severity
from .tool_directives import cross_tool_directive
from .tool_integrity import hidden_unicode_codepoints, injection_phrase

# Cap on strings walked inside one tool's schemas/annotations, so a hostile
# schema with thousands of string leaves cannot make analysis quadratic.
MAX_SCHEMA_STRINGS = 4096
_DISPLAY_NAME_CHARS = 80


def display_name(name: str) -> str:
    """A terminal-safe, bounded rendering of an untrusted tool name."""
    shown = name if len(name) <= _DISPLAY_NAME_CHARS else name[:_DISPLAY_NAME_CHARS] + "…"
    return repr(shown)


def _walk_strings(value: object, budget: list[int]) -> Iterator[str]:
    """Yield every string key/value in a JSON value, up to the shared budget."""
    stack: list[object] = [value]
    while stack and budget[0] > 0:
        node = stack.pop()
        if isinstance(node, str):
            budget[0] -= 1
            yield node
        elif isinstance(node, Mapping):
            for key, child in node.items():
                stack.append(child)
                if isinstance(key, str):
                    stack.append(key)
        elif isinstance(node, list):
            stack.extend(node)


def _surfaces(tool: LiveTool) -> Iterator[tuple[str, str]]:
    """Yield ``(surface_label, text)`` for every string the model reads for a tool."""
    yield ("the tool name", tool.name)
    yield ("the tool description", tool.description)
    budget = [MAX_SCHEMA_STRINGS]
    for label, value in (
        ("the input schema", tool.input_schema),
        ("the output schema", tool.output_schema),
        ("the annotations", tool.annotations),
    ):
        for text in _walk_strings(value, budget):
            yield (label, text)


def _hidden_finding(
    url: str, tool: LiveTool, surfaces: Sequence[str], codes: Sequence[int]
) -> Finding:
    listed = ", ".join(f"U+{cp:04X}" for cp in codes)
    where = ", ".join(surfaces)
    return Finding(
        id="LIVE-TOOL-HIDDEN-UNICODE",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title=f"Live tool {display_name(tool.name)}: hidden Unicode control characters in {where}",
        location=Location(path=url),
        remediation=(
            "Treat this server as compromised until reviewed: disable it in the host "
            "config, inspect the tool definition at its source, and re-enable only a "
            "version whose tool metadata is plain, visible text."
        ),
        rationale=(
            f"The running server advertises zero-width or bidirectional control characters "
            f"({listed}) that a human reviewing the tool list cannot see but the model reads "
            "verbatim — the hidden-instruction primitive behind tool-description poisoning."
        ),
    )


def _injection_finding(url: str, tool: LiveTool, surface: str, phrase: str) -> Finding:
    return Finding(
        id="LIVE-TOOL-INJECTION-TEXT",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        title=f"Live tool {display_name(tool.name)}: prompt-injection phrase in {surface}",
        location=Location(path=url),
        remediation=(
            "Disable the server and review the tool definition at its source. Tool "
            "metadata should describe the tool, never instruct the agent."
        ),
        rationale=(
            f'The running server tells the model "{phrase}" inside {surface}. Tool '
            "metadata is injected into the agent's context on every session, so this "
            "text can steer the agent without any user action (tool poisoning)."
        ),
    )


def _directive_finding(url: str, tool: LiveTool, surface: str, label: str) -> Finding:
    return Finding(
        id="LIVE-TOOL-CROSS-TOOL-DIRECTIVE",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.MEDIUM,
        title=f"Live tool {display_name(tool.name)}: directive steering other tools in {surface}",
        location=Location(path=url),
        remediation=(
            "Review the tool definition at its source. If the server has no legitimate "
            "reason to order or parameterize other tools, disable it; if it does, record "
            "an acceptance for this exact tool digest."
        ),
        rationale=(
            f"In {surface}, the running server's metadata {label}. Tool-poisoning attacks use such "
            "directives to make the agent call sensitive tools or tamper with arguments "
            "without any user action; benign servers rarely need them."
        ),
    )


def _duplicate_finding(url: str, name: str, count: int) -> Finding:
    return Finding(
        id="LIVE-TOOL-DUPLICATE-NAME",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.MEDIUM,
        title=f"Live tool {display_name(name)} is advertised {count} times by one server",
        location=Location(path=url),
        remediation=(
            "Report the duplicate to the server maintainer; until fixed, prefer a host "
            "that rejects ambiguous tool lists."
        ),
        rationale=(
            "Two definitions under one name make it ambiguous which description the "
            "model sees and which implementation runs — a reviewer can approve one "
            "while the agent calls the other."
        ),
    )


def _oversized_finding(url: str, tool: LiveTool) -> Finding:
    return Finding(
        id="LIVE-TOOL-OVERSIZED-DESCRIPTION",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.MEDIUM,
        title=(
            f"Live tool {display_name(tool.name)}: description exceeds "
            f"{MAX_DESCRIPTION_CHARS // 1024} KiB"
        ),
        location=Location(path=url),
        remediation=(
            "Review the full description at its source. A legitimate tool needs a few "
            "sentences; very long metadata is where instructions are hidden."
        ),
        rationale=(
            "An unusually long tool description is not readable in a host's approval "
            "dialog but is read in full by the model, so it can carry instructions a "
            "reviewer never sees."
        ),
    )


def _unavailable_finding(manifest: LiveManifest) -> Finding:
    return Finding(
        id="LIVE-TOOLS-UNAVAILABLE",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.LOW,
        title=f"Live tool manifest could not be captured ({manifest.error or 'unknown'})",
        location=Location(path=manifest.url or "live://refused"),
        remediation=(
            "Confirm the endpoint is a Streamable HTTP MCP server and the path is right "
            "(e.g. --live-tools-target 127.0.0.1:PORT/mcp). Servers that require "
            "authentication are not inspected: mcpscan never sends credentials."
        ),
        rationale=(
            "The live tool list was requested but not obtained, so this server's "
            "advertised tools were not inspected. Reported rather than skipped so the "
            "gap is visible."
        ),
    )


def _incomplete_finding(manifest: LiveManifest) -> Finding:
    detail = (
        f"{manifest.malformed_entries} malformed entr"
        f"{'y' if manifest.malformed_entries == 1 else 'ies'}"
        if manifest.malformed_entries
        else "a size, page or tool-count bound was reached"
    )
    return Finding(
        id="LIVE-TOOLS-INCOMPLETE",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.LOW,
        title=f"Live tool manifest only partially inspected ({detail})",
        location=Location(path=manifest.url),
        remediation=(
            "Review the server's full tool list manually. A server that advertises "
            "thousands of tools or malformed definitions warrants scrutiny on its own."
        ),
        rationale=(
            "Only the tools captured within mcpscan's bounds were inspected; anything "
            "beyond them was not analysed."
        ),
    )


def check_live_manifest(manifest: LiveManifest) -> list[Finding]:
    """Findings for one captured live manifest (deterministic order).

    One hidden-Unicode finding per tool (codepoints aggregated across its
    surfaces), one injection finding per (tool, surface), one cross-tool
    directive finding per (tool, surface) without an injection hit, plus duplicate-name,
    oversized-description, and capture-gap findings.
    """
    if not manifest.ok:
        return [_unavailable_finding(manifest)]

    findings: list[Finding] = []
    counts: dict[str, int] = {}
    for tool in manifest.tools:
        counts[tool.name] = counts.get(tool.name, 0) + 1

    for tool in sorted(manifest.tools, key=lambda t: (t.name, t.digest)):
        hidden: set[int] = set()
        hidden_surfaces: list[str] = []
        injected: dict[str, str] = {}
        directed: dict[str, str] = {}
        for surface, text in _surfaces(tool):
            codes = hidden_unicode_codepoints(text)
            if codes:
                hidden.update(codes)
                if surface not in hidden_surfaces:
                    hidden_surfaces.append(surface)
            phrase = injection_phrase(text)
            if phrase is not None and surface not in injected:
                injected[surface] = phrase
            directive = cross_tool_directive(text) if phrase is None else None
            if directive is not None and surface not in directed:
                directed[surface] = directive
        if hidden:
            findings.append(_hidden_finding(manifest.url, tool, hidden_surfaces, sorted(hidden)))
        for surface, phrase in injected.items():
            findings.append(_injection_finding(manifest.url, tool, surface, phrase))
        for surface, label in directed.items():
            if surface not in injected:  # a surface reports its strongest signal once
                findings.append(_directive_finding(manifest.url, tool, surface, label))
        if tool.description_oversized:
            findings.append(_oversized_finding(manifest.url, tool))

    for name in sorted(n for n, c in counts.items() if c > 1):
        findings.append(_duplicate_finding(manifest.url, name, counts[name]))
    if manifest.truncated:
        findings.append(_incomplete_finding(manifest))
    return findings


def check_cross_server_shadowing(manifests: Sequence[LiveManifest]) -> dict[str, list[Finding]]:
    """Flag tool names advertised by more than one live server.

    Returns ``{manifest url: [findings]}``. When two servers expose the same tool
    name, the model may route a call (and its arguments) to the wrong server —
    the cross-server shadowing class.
    """
    owners: dict[str, list[str]] = {}
    for manifest in manifests:
        if not manifest.ok:
            continue
        for name in sorted({t.name for t in manifest.tools}):
            owners.setdefault(name, []).append(manifest.url)
    result: dict[str, list[Finding]] = {}
    for name in sorted(owners):
        urls = sorted(set(owners[name]))
        if len(urls) < 2:
            continue
        for url in urls:
            others = ", ".join(u for u in urls if u != url)
            result.setdefault(url, []).append(
                Finding(
                    id="LIVE-TOOL-SHADOW",
                    dimension=Dimension.TOOL_SCOPE,
                    severity=Severity.MEDIUM,
                    title=f"Live tool {display_name(name)} is also advertised by {others}",
                    location=Location(path=url),
                    remediation=(
                        "Rename or disable one of the colliding tools, or keep the two "
                        "servers out of the same agent session."
                    ),
                    rationale=(
                        "When two connected servers expose the same tool name, a "
                        "malicious server can shadow a trusted one and receive calls — "
                        "and their arguments — intended for it."
                    ),
                )
            )
    return result
