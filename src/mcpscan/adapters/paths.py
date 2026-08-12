# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""OS-aware config-path resolution (ticket T-103).

This is the *only* place in the codebase that branches on operating system
(ARCHITECTURE.md §6). Paths are computed from an injected ``system`` string and
``env`` mapping so the resolver is fully unit-testable on any host.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePath, PurePosixPath, PureWindowsPath


def _home(system: str, env: Mapping[str, str]) -> PurePath | None:
    """Resolve the user's home directory from the environment, per OS."""
    if system == "Windows":
        userprofile = env.get("USERPROFILE")
        if userprofile:
            return PureWindowsPath(userprofile)
        drive, path = env.get("HOMEDRIVE"), env.get("HOMEPATH")
        if drive and path:
            return PureWindowsPath(drive + path)
        return None
    home = env.get("HOME")
    return PurePosixPath(home) if home else None


def claude_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return candidate Claude-ecosystem config paths for the given OS.

    Args:
        system: ``platform.system()`` value — ``"Darwin"``, ``"Linux"``, or
            ``"Windows"``.
        env: Environment mapping (e.g. ``os.environ``) supplying ``HOME`` /
            ``USERPROFILE`` / ``APPDATA``.

    Returns:
        Candidate paths in priority order. The caller checks which exist; a path
        being returned does not imply it is present.
    """
    home = _home(system, env)
    candidates: list[PurePath] = []

    if home is not None:
        # User-level Claude Code settings (cross-platform layout).
        candidates.append(home / ".claude" / "settings.json")
        candidates.append(home / ".claude" / "settings.local.json")

    # Claude Desktop config — location differs per OS.
    if system == "Darwin" and home is not None:
        candidates.append(
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
    elif system == "Windows":
        appdata = env.get("APPDATA")
        if appdata:
            candidates.append(PureWindowsPath(appdata) / "Claude" / "claude_desktop_config.json")
    elif home is not None:  # Linux and other POSIX
        candidates.append(home / ".config" / "Claude" / "claude_desktop_config.json")

    return candidates


def claude_credential_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return candidate Claude on-disk credential/token-store paths for the OS.

    Claude Code persists its OAuth login as a JSON token store at
    ``~/.claude/.credentials.json`` (the ``claudeAiOauth`` object with the
    access/refresh tokens and an ``expiresAt``) on every OS. On macOS the login
    is usually kept in the Keychain instead, so the file is often absent there —
    the caller checks existence, so returning the candidate on every OS is safe
    and conservative. This is the only credential store whose location is
    well-documented enough to name (Feature H registry seam); other hosts return
    the default ``[]`` rather than guess.
    """
    home = _home(system, env)
    if home is None:
        return []
    return [home / ".claude" / ".credentials.json"]


def cursor_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return the candidate user-level Cursor MCP config path for the given OS.

    Cursor uses a single global config at ``~/.cursor/mcp.json`` on every OS
    (``%USERPROFILE%\\.cursor\\mcp.json`` on Windows).
    """
    home = _home(system, env)
    if home is None:
        return []
    return [home / ".cursor" / "mcp.json"]


def windsurf_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return the candidate user-level Windsurf MCP config path for the given OS.

    Windsurf (Codeium) uses a single global config at
    ``~/.codeium/windsurf/mcp_config.json`` on every OS.
    """
    home = _home(system, env)
    if home is None:
        return []
    return [home / ".codeium" / "windsurf" / "mcp_config.json"]


def _vscode_user_dir(system: str, env: Mapping[str, str]) -> PurePath | None:
    """Return the VS Code ``User`` profile directory for the given OS, or None.

    OS-specific, mirroring the Claude Desktop layout: ``Application Support`` on
    macOS, ``%APPDATA%`` on Windows, ``~/.config`` elsewhere. Shared by the Cline
    (a VS Code extension) and native VS Code MCP adapters.
    """
    if system == "Darwin":
        home = _home(system, env)
        return None if home is None else home / "Library" / "Application Support" / "Code" / "User"
    if system == "Windows":
        appdata = env.get("APPDATA")
        return None if not appdata else PureWindowsPath(appdata) / "Code" / "User"
    home = _home(system, env)  # Linux and other POSIX
    return None if home is None else home / ".config" / "Code" / "User"


def cline_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return the candidate user-level Cline MCP config path for the given OS.

    Cline is a VS Code extension (``saoudrizwan.claude-dev``) that stores its MCP
    servers under the editor's ``globalStorage``.
    """
    user_dir = _vscode_user_dir(system, env)
    if user_dir is None:
        return []
    return [
        user_dir
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
        / "cline_mcp_settings.json"
    ]


def vscode_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return the candidate user-level VS Code MCP config path for the given OS.

    VS Code's native MCP support keeps user-level servers in ``mcp.json`` under
    the editor's ``User`` profile directory (workspace servers live in
    ``.vscode/mcp.json``, resolved per-project by the adapter).
    """
    user_dir = _vscode_user_dir(system, env)
    if user_dir is None:
        return []
    return [user_dir / "mcp.json"]


def zed_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return the candidate user-level Zed settings path for the given OS.

    Zed keeps MCP servers (``context_servers``) in its main ``settings.json``.
    Notably Zed uses ``~/.config/zed`` on **both** macOS and Linux (not
    ``~/Library/Application Support``); on Windows it is ``%APPDATA%\\Zed``.
    Workspace servers live in ``.zed/settings.json``, resolved per-project by the
    adapter.
    """
    if system == "Windows":
        appdata = env.get("APPDATA")
        if not appdata:
            return []
        return [PureWindowsPath(appdata) / "Zed" / "settings.json"]
    home = _home(system, env)  # macOS and Linux both use ~/.config/zed
    if home is None:
        return []
    return [home / ".config" / "zed" / "settings.json"]


def continue_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return the candidate user-level Continue MCP config path for the given OS.

    Continue keeps its config in the home-dir ``.continue`` folder on every OS
    (``%USERPROFILE%\\.continue`` on Windows) — not ``~/Library`` or ``%APPDATA%``.
    The current format is ``config.yaml``; project servers live in
    ``.continue/config.yaml``, resolved per-project by the adapter.
    """
    home = _home(system, env)
    if home is None:
        return []
    return [home / ".continue" / "config.yaml"]
