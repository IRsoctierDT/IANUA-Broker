# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Inspection-health check: a config the scanner could not read or parse.

FR-C1's acceptance criterion is that a malformed or oversized host config is
"reported as a ``parse_error`` finding, never crash the run". The crash half is
handled at the parse boundary (``adapters.base.decode_config``, ``io_safe``);
this module is the reporting half.

Why it matters more than a tidy log line: **silence is evasion**. A config the
scanner cannot parse is still a config the *host* may load — MCP hosts are
tolerant of shapes ``json.loads`` rejects, and a size cap or a permission bit is
attacker-influenceable. If an unreadable config simply vanished from the report,
the cheapest way to hide a wildcard auto-approval or a plaintext key from the
scanner would be to make its file unparseable: the operator would see grade A
and exit code 0 over a surface that was never inspected. So an unreadable config
becomes a visible finding and rides ``inspection_incomplete``: the report says "I
could not look here", which is a different statement from "there is nothing here".

Pure over its inputs (the read/parse edges live in the engine), and the failure
detail is quoted verbatim rather than interpreted — it may contain
attacker-chosen text, which the renderers neutralize on the way out.
"""

from __future__ import annotations

from ..domain import Dimension, Finding, Location, Severity


def check_config_readable(path: str, failure: str | None) -> list[Finding]:
    """Flag a host config that exists but could not be read or parsed.

    Args:
        path: The config file's path, as the report should name it.
        failure: Why the file could not be used (an ``io_safe`` refusal or an
            adapter ``parse_error``), or ``None`` when it was read fine.

    Returns:
        One MEDIUM ``CONFIG-UNREADABLE`` finding, or an empty list when
        ``failure`` is ``None``. MEDIUM rather than HIGH because an unreadable
        config is an *inspection gap*, not a proven weakness — it must be seen
        and graded, but it should not fail a CI gate on its own (the default
        ``--fail-on high``); the accompanying ``inspection_incomplete`` flag is
        what tells the operator the surface was skipped.
    """
    if failure is None:
        return []
    return [
        Finding(
            id="CONFIG-UNREADABLE",
            dimension=Dimension.TOOL_SCOPE,
            severity=Severity.MEDIUM,
            title="Host config could not be read or parsed",
            location=Location(path=path),
            remediation=(
                "Repair the file so it parses (validate its JSON/YAML), or restore "
                "read access and keep it under the size cap. Until then this "
                "config's servers, permissions, and secrets are un-inspected — "
                "review it by hand."
            ),
            rationale=(
                f"The scanner could not inspect this config: {failure}. An agent "
                "host may still load it, so any auto-approval, permission grant, "
                "or plaintext credential inside is unaudited — an unparseable "
                "file is the cheapest way to hide a server from a scanner."
            ),
        )
    ]
