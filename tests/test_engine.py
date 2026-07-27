"""Engine + Claude adapter integration tests (T-204/205, golden/clean — T-212)."""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
from pathlib import Path

import pytest

import mcpscan.engine as engine_mod
from mcpscan.adapters.claude import ClaudeAdapter
from mcpscan.discovery.sockets import EnumerationResult, ListeningSocket
from mcpscan.domain import Dimension, ServerState
from mcpscan.engine import discover_host_config_files, scan

VULN_CONFIG = {
    "mcpServers": {
        "leaky": {
            "command": "npx",
            "args": ["-y", "some-mcp-server"],
            "env": {"OPENAI_API_KEY": "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123"},
        }
    },
    "permissions": {"allow": ["Bash(*)"]},
}

CLEAN_CONFIG = {
    "mcpServers": {
        "safe": {
            "command": "npx",
            "args": ["-y", "some-mcp-server@1.2.3"],
            "env": {"LOG_LEVEL": "info"},
        }
    },
    "permissions": {"allow": ["Read", "Glob(src/**)"]},
}


def test_adapter_parses_servers_and_permissions() -> None:
    cfg = ClaudeAdapter().parse("/cfg.json", json.dumps(VULN_CONFIG))
    assert cfg.servers[0].name == "leaky"
    assert cfg.allow_permissions == ("Bash(*)",)


def test_adapter_never_raises_on_bad_json() -> None:
    cfg = ClaudeAdapter().parse("/cfg.json", "{not json")
    assert cfg.parse_error is not None
    assert cfg.servers == ()


def _scan_root(tmp_path: Path, config: dict[str, object]) -> object:
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    return scan(
        roots=[tmp_path],
        system="Linux",
        env={},  # no HOME -> no user configs, deterministic
        enumerate_sockets=False,  # no psutil/network in tests
    )


def test_vulnerable_config_grades_f_with_expected_findings(tmp_path: Path) -> None:
    report = _scan_root(tmp_path, VULN_CONFIG)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-PLAINTEXT" in ids  # plaintext OpenAI key
    assert "SCOPE-DANGEROUS-ALLOW" in ids  # Bash(*) auto-allowed
    assert "PIN-UNPINNED" in ids  # npx -y with no version
    assert report.overall_grade == "F"  # a Critical secret => F


def test_clean_config_grades_a_with_zero_findings(tmp_path: Path) -> None:
    # T-212 golden clean fixture: a well-configured setup must be silent.
    report = _scan_root(tmp_path, CLEAN_CONFIG)
    all_findings = [f for s in report.servers for f in s.findings]
    assert all_findings == []
    assert report.overall_grade == "A"


def test_scan_is_deterministic(tmp_path: Path) -> None:
    a = _scan_root(tmp_path, VULN_CONFIG)
    b = _scan_root(tmp_path, VULN_CONFIG)
    assert a == b


# --- orchestration wiring the pure-check tests bypass ---
def test_running_socket_exposure_lands_in_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An exposed listening socket becomes a RUNNING server with an exposure finding.
    monkeypatch.setattr(
        engine_mod,
        "enumerate_listening",
        lambda: EnumerationResult(
            sockets=(ListeningSocket("0.0.0.0", 8000, 100, "node"),),  # noqa: S104
            inspection_incomplete=False,
        ),
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=True)
    running = [s for s in report.servers if s.running]
    assert len(running) == 1
    assert running[0].bind_addr == "0.0.0.0"  # noqa: S104
    assert running[0].state is ServerState.RUNNING
    assert any(f.dimension is Dimension.EXPOSURE for f in running[0].findings)


def test_loopback_socket_is_not_surfaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A loopback bind has no exposure, so it must not appear as a server.
    monkeypatch.setattr(
        engine_mod,
        "enumerate_listening",
        lambda: EnumerationResult(
            sockets=(ListeningSocket("127.0.0.1", 8000, 100, "node"),),
            inspection_incomplete=False,
        ),
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=True)
    assert [s for s in report.servers if s.running] == []


def test_user_level_config_is_discovered(tmp_path: Path) -> None:
    # Drive the OS-default config discovery loop via system/env overrides.
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(json.dumps(VULN_CONFIG), encoding="utf-8")
    report = scan(roots=[], system="Darwin", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-PLAINTEXT" in ids


def test_env_file_in_project_root_is_audited(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX0123\n", encoding="utf-8"
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    env_servers = [s for s in report.servers if s.id.endswith(".env")]
    assert len(env_servers) == 1
    assert any(f.id == "CRED-PLAINTEXT" for f in env_servers[0].findings)


_GIT = shutil.which("git")


def _git(tmp_path: Path, *args: str) -> None:
    assert _GIT is not None
    subprocess.run(  # nosec B603 (fixed argv, no shell)
        [_GIT, "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
    )


@pytest.mark.skipif(_GIT is None, reason="git not installed")
def test_git_tracked_secret_env_file_is_flagged(tmp_path: Path) -> None:
    # T-207: a committed .env holding a secret must surface CRED-GIT through
    # the real scan pipeline, not just the unit-level check.
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX0123\n", encoding="utf-8"
    )
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".env")
    _git(tmp_path, "commit", "-qm", "x")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-GIT" in ids


@pytest.mark.skipif(_GIT is None, reason="git not installed")
def test_untracked_secret_env_file_is_not_git_flagged(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX0123\n", encoding="utf-8"
    )
    _git(tmp_path, "init", "-q")  # a repo, but the .env is not committed
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-GIT" not in ids
    assert "CRED-PLAINTEXT" in ids  # the secret itself is still flagged


def test_env_file_outside_git_repo_has_unknown_tracking(tmp_path: Path) -> None:
    # No repo -> git_tracked stays unknown (None): no CRED-GIT, no crash.
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX0123\n", encoding="utf-8"
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-GIT" not in ids


def test_git_tracked_none_when_git_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod.shutil, "which", lambda _: None)
    assert engine_mod._git_tracked(tmp_path / ".env") is None


def test_unreadable_config_is_skipped(tmp_path: Path) -> None:
    # A path that exists but can't be safely read (here: a directory named
    # like a config) is skipped gracefully rather than crashing the scan.
    (tmp_path / ".mcp.json").mkdir()
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    assert report.servers == ()
    assert report.overall_grade == "A"


# --- Cursor host adapter (second adapter, ADR-4) ---
CURSOR_VULN = {
    "mcpServers": {
        "leaky": {
            "command": "npx",
            "args": ["-y", "db-mcp-server"],
            "env": {"POSTGRES_PASSWORD": "S3cr3t-Pa55w0rd-abcdef123456"},
        }
    }
}


def test_cursor_project_config_is_discovered(tmp_path: Path) -> None:
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    leaky = [s for s in report.servers if s.id.endswith("#leaky")]
    assert len(leaky) == 1
    assert "mcp.json" in leaky[0].id and ".cursor" in leaky[0].id
    ids = {f.id for f in leaky[0].findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


def test_cursor_and_claude_project_configs_coexist(tmp_path: Path) -> None:
    # Both adapters run over the same project root, each on its own file.
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    (tmp_path / ".mcp.json").write_text(json.dumps(CLEAN_CONFIG), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    names = {s.id.rsplit("#", 1)[-1] for s in report.servers}
    assert {"leaky", "safe"} <= names  # cursor's leaky + claude's safe


def test_cursor_user_level_config_is_discovered(tmp_path: Path) -> None:
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-PLAINTEXT" in ids


def test_windsurf_user_level_config_is_discovered(tmp_path: Path) -> None:
    # Windsurf's global config at ~/.codeium/windsurf/mcp_config.json.
    ws_dir = tmp_path / ".codeium" / "windsurf"
    ws_dir.mkdir(parents=True)
    (ws_dir / "mcp_config.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


def test_discover_host_config_files_finds_project_and_user_configs(tmp_path: Path) -> None:
    # Project .mcp.json + .cursor/mcp.json, plus a user-level Cursor config.
    (tmp_path / ".mcp.json").write_text(json.dumps(CLEAN_CONFIG), encoding="utf-8")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    files = discover_host_config_files(
        roots=[tmp_path], system="Linux", env={"HOME": str(tmp_path)}
    )
    names = {p.name for p in files}
    assert "mcp.json" in names and ".mcp.json" in names
    # No duplicates, and .env is never included (host configs only).
    assert len(files) == len(set(files))
    assert not any(p.name == ".env" for p in files)


def test_discover_host_config_files_skips_missing(tmp_path: Path) -> None:
    # Nothing on disk -> empty list, never a crash.
    assert discover_host_config_files(roots=[tmp_path], system="Linux", env={}) == []


def test_cline_user_level_config_is_discovered(tmp_path: Path) -> None:
    # Cline's global config lives under the VS Code globalStorage tree.
    cline_dir = (
        tmp_path
        / ".config"
        / "Code"
        / "User"
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
    )
    cline_dir.mkdir(parents=True)
    (cline_dir / "cline_mcp_settings.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


# --- VS Code host adapter (native MCP, "servers" shape) ---
VSCODE_VULN = {
    "servers": {
        "leaky": {
            "command": "npx",
            "args": ["-y", "db-mcp-server"],
            "env": {"POSTGRES_PASSWORD": "S3cr3t-Pa55w0rd-abcdef123456"},
        }
    }
}


def test_vscode_project_config_is_discovered(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "mcp.json").write_text(json.dumps(VSCODE_VULN), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    leaky = [s for s in report.servers if s.id.endswith("#leaky")]
    assert len(leaky) == 1
    assert "mcp.json" in leaky[0].id and ".vscode" in leaky[0].id
    ids = {f.id for f in leaky[0].findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


def test_vscode_user_level_config_is_discovered(tmp_path: Path) -> None:
    # VS Code's user-level mcp.json under the Code User profile dir.
    user_dir = tmp_path / ".config" / "Code" / "User"
    user_dir.mkdir(parents=True)
    (user_dir / "mcp.json").write_text(json.dumps(VSCODE_VULN), encoding="utf-8")
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


# --- Zed host adapter (native MCP, "context_servers" shape, JSONC) ---
ZED_VULN = {
    "context_servers": {
        "leaky": {
            "command": "npx",
            "args": ["-y", "db-mcp-server"],
            "env": {"POSTGRES_PASSWORD": "S3cr3t-Pa55w0rd-abcdef123456"},
        }
    }
}


def test_zed_project_config_is_discovered(tmp_path: Path) -> None:
    zed_dir = tmp_path / ".zed"
    zed_dir.mkdir()
    (zed_dir / "settings.json").write_text(json.dumps(ZED_VULN), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    leaky = [s for s in report.servers if s.id.endswith("#leaky")]
    assert len(leaky) == 1
    assert "settings.json" in leaky[0].id and ".zed" in leaky[0].id
    ids = {f.id for f in leaky[0].findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


def test_zed_user_level_jsonc_config_is_discovered(tmp_path: Path) -> None:
    # User settings at ~/.config/zed/settings.json, written as JSONC (comments).
    zed_dir = tmp_path / ".config" / "zed"
    zed_dir.mkdir(parents=True)
    body = "{\n  // my servers\n  " + json.dumps(ZED_VULN)[1:-1] + ",\n}"
    (zed_dir / "settings.json").write_text(body, encoding="utf-8")
    report = scan(roots=[], system="Darwin", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


# --- Continue host adapter (YAML "mcpServers" list; [yaml] extra) ---
CONTINUE_VULN = """
name: cfg
mcpServers:
  - name: leaky
    command: npx
    args: ["-y", "db-mcp-server"]
    env:
      POSTGRES_PASSWORD: S3cr3t-Pa55w0rd-abcdef123456
"""


def test_continue_project_config_is_discovered(tmp_path: Path) -> None:
    cont_dir = tmp_path / ".continue"
    cont_dir.mkdir()
    (cont_dir / "config.yaml").write_text(CONTINUE_VULN, encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    leaky = [s for s in report.servers if s.id.endswith("#leaky")]
    assert len(leaky) == 1
    assert "config.yaml" in leaky[0].id and ".continue" in leaky[0].id
    ids = {f.id for f in leaky[0].findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


def test_continue_user_level_config_is_discovered(tmp_path: Path) -> None:
    cont_dir = tmp_path / ".continue"
    cont_dir.mkdir()
    (cont_dir / "config.yaml").write_text(CONTINUE_VULN, encoding="utf-8")
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids
