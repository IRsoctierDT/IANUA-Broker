# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Running-process environment enumeration (Wave 2 Feature G, CRED-ENV).

The "quiet credential read" surface: an agent or MCP host that receives its API
keys through the *process environment* leaves those secrets legible to anything
that can read the process — the classic ``/proc/<pid>/environ`` leak. This helper
enumerates the environment blocks of the machine's own running agent/MCP
processes so a pure check (:func:`mcpscan.checks.secrets.check_process_env_secrets`)
can grade them.

Two guardrails keep this narrow and safe:

- **Scope** — only processes whose name/cmdline looks like an agent/MCP host or
  MCP server are inspected (see :func:`looks_like_agent`); a bare ``python`` or
  ``node`` with no agent marker is skipped, so this never sweeps every process on
  the machine. An environment block is read *only after* the agent predicate
  matches, so no non-agent process's env is ever touched.
- **Privilege** — only the invoking user's own processes are readable without
  root; other users' processes raise ``AccessDenied`` and are skipped (with
  ``inspection_incomplete`` set). That own-user scope is the intended boundary.

The thin psutil edge mirrors ``discovery/sockets.py``: it never raises — any
per-process denial degrades to a skip, and a missing/failing psutil degrades to
an empty result flagged incomplete (FR-D1). Raw secret values are never handled
here; this module only carries the ``(key, value)`` pairs onward to the pure
check, which fingerprints them at detection.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

# Substrings that mark a process as an agent/MCP host or an MCP server. Matched
# case-insensitively against the process name joined with its cmdline. Kept
# deliberately small and specific: an MCP server launched via node/npx/uvx/python
# carries its package name (almost always containing "mcp"/"modelcontextprotocol")
# on the cmdline, and an agent host app carries its product name — so requiring an
# agent marker (rather than just a runtime like "python") is what stops this from
# scanning every process on the box.
_AGENT_MARKERS: tuple[str, ...] = (
    "mcp",
    "modelcontextprotocol",
    "model-context-protocol",
    "claude",
    "cursor",
    "windsurf",
    "cline",
    "continue",
    "zed",
)

# Match each marker only at word boundaries, so a short marker never fires on a
# coincidental substring of an unrelated word — "zed" must not match
# "authoriZED"/"synchroniZED", "cursor" must not match "preCURSOR", "cline" must
# not match "deCLINE". `\b` sits between a word char and a non-word char, and the
# separators in real package names (`-`, `/`, `.`, space, `@`) are all non-word,
# so "mcp-server", "@modelcontextprotocol/x", and "claude.app" still match.
_AGENT_MARKER_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(m) for m in _AGENT_MARKERS) + r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ProcessEnv:
    """One running process's environment, reduced to its (key, value) pairs.

    ``env`` holds the raw pairs only long enough to reach the pure secret check,
    which fingerprints any secret at detection; nothing downstream retains a raw
    value.
    """

    pid: int
    proc_name: str
    env: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ProcessEnvResult:
    """Enumerated agent-process envs plus whether introspection was complete."""

    entries: tuple[ProcessEnv, ...]
    inspection_incomplete: bool = False


def looks_like_agent(text: str) -> bool:
    """True if ``text`` (a process name + cmdline) names an agent/MCP process.

    Pure and case-insensitive. This is the scope guardrail: it must be *positive*
    identification, so a process with no agent marker is skipped and its
    environment is never read. Markers match only at word boundaries, so a short
    marker cannot fire on a coincidental substring (e.g. "zed" in "authorized").
    """
    return _AGENT_MARKER_RE.search(text) is not None


def iter_agent_process_envs(is_agent: Callable[[str], bool]) -> ProcessEnvResult:
    """Enumerate the environments of running agent/MCP processes, degrading safely.

    For each running process, the (name + cmdline) haystack is classified by
    ``is_agent`` **before** its environment is read — so only agent/MCP processes
    have their env inspected. Own-user processes are readable without root; any
    other process (or one that exits mid-scan) raises ``AccessDenied`` /
    ``NoSuchProcess`` and is skipped, with ``inspection_incomplete`` set. Never
    raises: a missing or wholly-denied psutil yields an empty, incomplete result.
    """
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is a declared dependency
        return ProcessEnvResult(entries=(), inspection_incomplete=True)

    incomplete = False
    entries: list[ProcessEnv] = []
    try:
        procs = psutil.process_iter()
    except (psutil.Error, OSError):
        return ProcessEnvResult(entries=(), inspection_incomplete=True)

    for proc in procs:
        try:
            name = proc.name()
            haystack = " ".join([name, *proc.cmdline()])
            if not is_agent(haystack):
                continue
            # Only reached for agent/MCP processes: the env is read here, never
            # for a process the guardrail rejected above.
            environ = proc.environ()
            pid = proc.pid
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            incomplete = True
            continue
        entries.append(ProcessEnv(pid=pid, proc_name=name, env=tuple(environ.items())))

    return ProcessEnvResult(entries=tuple(entries), inspection_incomplete=incomplete)
