# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Opt-in remediation (``--fix``) for over-broad tool-scope grants.

The tool is advise-only by default; ``--fix`` is the single, explicit exception
that writes to a config. It applies only **safe, deterministic, reversible**
edits — removing shell/exec-class and wildcard entries from ``permissions.allow``
and each server's ``autoApprove`` — using the very same predicates the tool-scope
*check* uses, so a fixed config re-scans clean. Nothing is invented: credential
and pinning findings are deliberately **not** auto-fixed (a safe rewrite needs a
new home for the secret or a specific version we can't know offline), so those
stay manual.

Planning (:func:`plan_config_fixes`) is pure and never raises. Applying
(:func:`apply_fix_to_file`) is the only write path; it backs up the original
first and preserves the file's permissions.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .checks.tool_scope import has_broad_wildcard, is_dangerous_tool

BACKUP_SUFFIX = ".mcpscan.bak"


@dataclass(frozen=True)
class AppliedFix:
    """One safe edit the fixer made (or would make) to a config."""

    rule_id: str  # the check id this remediates, e.g. SCOPE-DANGEROUS-ALLOW
    where: str  # dotted location, e.g. "permissions.allow" or "mcpServers.weather.autoApprove"
    removed: str  # the entry that was removed


@dataclass(frozen=True)
class FixPlan:
    """The result of planning fixes for one config file."""

    path: str
    fixes: tuple[AppliedFix, ...] = ()
    new_text: str | None = None  # rewritten config text, or None when nothing changed
    error: str | None = None  # parse/shape problem — the file is left untouched

    @property
    def changed(self) -> bool:
        return self.new_text is not None and bool(self.fixes)


def _rule_for(entry: str, *, dangerous_id: str, wildcard_id: str) -> str | None:
    """The check id an entry would be flagged under, or None if it is safe.

    Mirrors the checker's precedence exactly (dangerous before wildcard) so the
    rule id reported by ``--fix`` matches what a scan would emit.
    """
    if is_dangerous_tool(entry):
        return dangerous_id
    if has_broad_wildcard(entry):
        return wildcard_id
    return None


def _prune_list(
    raw_list: list[object], where: str, *, dangerous_id: str, wildcard_id: str
) -> tuple[list[object], list[AppliedFix]]:
    """Drop unsafe string entries from an allow/autoApprove list, preserving order.

    Non-string entries (shapes we don't understand) are kept untouched. Callers
    guarantee ``raw_list`` is a list.
    """
    kept: list[object] = []
    fixes: list[AppliedFix] = []
    for entry in raw_list:
        rule_id = (
            _rule_for(entry, dangerous_id=dangerous_id, wildcard_id=wildcard_id)
            if isinstance(entry, str)
            else None
        )
        if rule_id is not None:
            fixes.append(AppliedFix(rule_id=rule_id, where=where, removed=str(entry)))
        else:
            kept.append(entry)
    return kept, fixes


def plan_config_fixes(path: str, raw: str) -> FixPlan:
    """Compute the safe tool-scope edits for one config file (pure; never raises).

    Returns a :class:`FixPlan`. ``new_text`` is populated only when at least one
    entry is removed; on malformed JSON or an unexpected root shape the file is
    reported untouched via ``error``.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        return FixPlan(path=path, error=f"invalid JSON: {exc}")
    except RecursionError:
        # Deeply-nested JSON overflows the decoder. RecursionError is a
        # RuntimeError, not a ValueError — and this function writes to the
        # user's config, so "never raises" must hold on hostile input too: the
        # file is reported untouched rather than crashing mid-remediation.
        return FixPlan(path=path, error="config nesting is too deep to parse")
    if not isinstance(data, dict):
        return FixPlan(path=path, error="config root is not an object")

    fixes: list[AppliedFix] = []

    # Config-level permission allow-list (Claude ecosystem).
    perms = data.get("permissions")
    if isinstance(perms, dict):
        allow = perms.get("allow")
        if isinstance(allow, list):
            kept, applied = _prune_list(
                allow,
                "permissions.allow",
                dangerous_id="SCOPE-DANGEROUS-ALLOW",
                wildcard_id="SCOPE-WILDCARD",
            )
            if applied:
                perms["allow"] = kept
                fixes.extend(applied)

    # Per-server autoApprove lists.
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            auto = spec.get("autoApprove")
            if not isinstance(auto, list):
                continue
            where = f"mcpServers.{name}.autoApprove"
            kept, applied = _prune_list(
                auto,
                where,
                dangerous_id="SCOPE-DANGEROUS-AUTOAPPROVE",
                wildcard_id="SCOPE-AUTOAPPROVE-WILDCARD",
            )
            if applied:
                spec["autoApprove"] = kept
                fixes.extend(applied)

    if not fixes:
        return FixPlan(path=path)  # nothing to do — file left as-is

    # Preserve key order (json keeps insertion order); only whitespace is normalized.
    new_text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    return FixPlan(path=path, fixes=tuple(fixes), new_text=new_text)


def apply_fix_to_file(path: Path, new_text: str) -> Path:
    """Write ``new_text`` to ``path``, backing up the original first.

    The original is copied to ``<path>.mcpscan.bak`` (content + mode preserved),
    then the new content is written atomically via a temp file + ``os.replace``,
    keeping the file's original permission bits. Returns the backup path.
    """
    backup = Path(str(path) + BACKUP_SUFFIX)
    shutil.copy2(path, backup)  # preserves original contents, mode, and mtime
    mode = stat.S_IMODE(path.stat().st_mode)
    tmp = Path(str(path) + ".mcpscan.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(new_text)
        os.replace(tmp, path)
    finally:
        if tmp.exists():  # pragma: no cover - only if os.replace failed
            tmp.unlink()
    return backup
