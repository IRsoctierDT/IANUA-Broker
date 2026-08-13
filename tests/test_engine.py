# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Engine + Claude adapter integration tests (T-204/205, golden/clean — T-212)."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess  # nosec B404
from pathlib import Path

import pytest

import mcpscan.engine as engine_mod
from mcpscan.adapters.claude import ClaudeAdapter
from mcpscan.discovery.sockets import EnumerationResult, ListeningSocket
from mcpscan.domain import Dimension, ServerState
from mcpscan.engine import discover_host_config_files, scan
from mcpscan.scoring import grade_findings

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
            sockets=(ListeningSocket("0.0.0.0", 8000, 100, "node"),),
            inspection_incomplete=False,
        ),
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=True)
    running = [s for s in report.servers if s.running]
    assert len(running) == 1
    assert running[0].bind_addr == "0.0.0.0"
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


# --- CRED-REUSE blast radius through the full pipeline (Wave 1 Feature C) ---
REUSED_KEY = "sk-ant-api03-REUSEDACROSSSERVERSABCDEFGHIJ0123456789"


def test_reused_secret_across_configs_flags_both_and_lowers_grade(tmp_path: Path) -> None:
    claude_cfg = {
        "mcpServers": {
            "one": {"command": "npx", "args": ["a-mcp@1.0.0"], "env": {"API_KEY": REUSED_KEY}}
        }
    }
    cursor_cfg = {
        "mcpServers": {
            "two": {"command": "npx", "args": ["b-mcp@1.0.0"], "env": {"TOKEN": REUSED_KEY}}
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(claude_cfg), encoding="utf-8")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps(cursor_cfg), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    assert len(report.servers) == 2
    for server in report.servers:
        ids = {f.id for f in server.findings}
        assert {"CRED-PLAINTEXT", "CRED-REUSE"} <= ids
        # Grade impact is visible: CRITICAL(40) + MEDIUM(10) -> score 50 -> F,
        # where the lone CRED-PLAINTEXT would have graded D. Reuse detection
        # runs before grading, so the blast radius is priced in.
        assert grade_findings(server.findings) == "F"
    assert report.overall_grade == "F"


def test_reused_secret_between_env_file_and_config_server(tmp_path: Path) -> None:
    # The join spans surfaces: a .env "server" and a declared config server.
    cfg = {
        "mcpServers": {
            "one": {"command": "npx", "args": ["a-mcp@1.0.0"], "env": {"API_KEY": REUSED_KEY}}
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text(f"ANTHROPIC_API_KEY={REUSED_KEY}\n", encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    by_id = {s.id: {f.id for f in s.findings} for s in report.servers}
    env_ids = next(ids for sid, ids in by_id.items() if sid.endswith(".env"))
    cfg_ids = next(ids for sid, ids in by_id.items() if sid.endswith("#one"))
    assert "CRED-REUSE" in env_ids
    assert "CRED-REUSE" in cfg_ids


def test_distinct_secrets_across_configs_are_not_reuse(tmp_path: Path) -> None:
    claude_cfg = {
        "mcpServers": {
            "one": {"command": "npx", "args": ["a-mcp@1.0.0"], "env": {"API_KEY": REUSED_KEY}}
        }
    }
    cursor_cfg = {
        "mcpServers": {
            "two": {
                "command": "npx",
                "args": ["b-mcp@1.0.0"],
                "env": {"TOKEN": "sk-ant-api03-ANENTIRELYDIFFERENTSECRET9876543210"},
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(claude_cfg), encoding="utf-8")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps(cursor_cfg), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    assert not any(f.id == "CRED-REUSE" for s in report.servers for f in s.findings)


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


# --- token/credential store inspection (Wave 2 Feature H; opt-in) ---
def _jwt(payload: dict[str, object]) -> str:
    def seg(obj: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode("ascii")

    return f"{seg({'alg': 'none'})}.{seg(payload)}.sig"


def _write_claude_credentials(tmp_path: Path, body: str, *, mode: int) -> Path:
    cred_dir = tmp_path / ".claude"
    cred_dir.mkdir(exist_ok=True)
    cred = cred_dir / ".credentials.json"
    cred.write_text(body, encoding="utf-8")
    cred.chmod(mode)
    return cred


def _token_store_servers(report: object) -> list[object]:
    return [s for s in report.servers if s.id.startswith("token-store://")]  # type: ignore[attr-defined]


@pytest.mark.skipif(
    os.name != "posix",
    reason="world/group-readable is a POSIX mode concept; Windows chmod is a no-op",
)
def test_token_store_world_readable_flags_perms(tmp_path: Path) -> None:
    _write_claude_credentials(
        tmp_path, json.dumps({"claudeAiOauth": {"accessToken": "sk-ant-oat-opaque"}}), mode=0o644
    )
    report = scan(
        roots=[],
        system="Linux",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_token_stores=True,
        now_epoch=2_000_000_000,
    )
    stores = _token_store_servers(report)
    assert len(stores) == 1
    assert stores[0].id.endswith(".claude/.credentials.json")
    assert {f.id for f in stores[0].findings} == {"TOKEN-STORE-PERMS"}


def test_token_store_expired_jwt_flags_expired(tmp_path: Path) -> None:
    body = json.dumps({"claudeAiOauth": {"accessToken": _jwt({"exp": 1_000_000_000})}})
    _write_claude_credentials(tmp_path, body, mode=0o600)  # safe perms -> expiry only
    report = scan(
        roots=[],
        system="Linux",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_token_stores=True,
        now_epoch=2_000_000_000,
    )
    stores = _token_store_servers(report)
    assert len(stores) == 1
    assert {f.id for f in stores[0].findings} == {"TOKEN-STORE-EXPIRED"}


def test_token_store_not_read_without_optin(tmp_path: Path) -> None:
    # Default scan reads nothing new: the store never appears, even world-readable.
    _write_claude_credentials(
        tmp_path, json.dumps({"claudeAiOauth": {"accessToken": "sk-ant-oat-opaque"}}), mode=0o644
    )
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    assert _token_store_servers(report) == []


def test_token_store_safe_and_undecodable_yields_no_server(tmp_path: Path) -> None:
    # 0o600 + no decodable token: presence is not a vulnerability -> no server.
    _write_claude_credentials(tmp_path, "%%% not json, not a jwt %%%", mode=0o600)
    report = scan(
        roots=[],
        system="Linux",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_token_stores=True,
        now_epoch=2_000_000_000,
    )
    assert _token_store_servers(report) == []


def test_token_store_absent_file_is_silent(tmp_path: Path) -> None:
    # No credentials file at all: opt-in on, but nothing to grade -> no crash.
    report = scan(
        roots=[],
        system="Linux",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_token_stores=True,
        now_epoch=2_000_000_000,
    )
    assert _token_store_servers(report) == []


# --- process-env secret detection (Wave 2 Feature G, CRED-ENV) ---
_PROC_KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _process_servers(report: object) -> list[object]:
    return [s for s in report.servers if s.id.startswith("process://")]  # type: ignore[attr-defined]


def _stub_process_envs(monkeypatch: pytest.MonkeyPatch, result: object) -> list[bool]:
    """Replace the engine's process-env enumerator; record whether it was called."""
    from mcpscan.discovery.process_env import ProcessEnvResult

    called: list[bool] = []

    def _fake(is_agent: object) -> object:
        called.append(True)
        return result if result is not None else ProcessEnvResult(entries=())

    monkeypatch.setattr(engine_mod, "iter_agent_process_envs", _fake)
    return called


def test_process_env_secret_flags_cred_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpscan.discovery.process_env import ProcessEnv, ProcessEnvResult

    entry = ProcessEnv(pid=42, proc_name="claude", env=(("ANTHROPIC_API_KEY", _PROC_KEY),))
    _stub_process_envs(monkeypatch, ProcessEnvResult(entries=(entry,)))
    report = scan(
        roots=[], system="Linux", env={}, enumerate_sockets=False, inspect_process_env=True
    )
    servers = _process_servers(report)
    assert len(servers) == 1
    assert servers[0].id == "process://claude:42"
    assert servers[0].running is True
    assert {f.id for f in servers[0].findings} == {"CRED-ENV"}


def test_process_env_not_read_without_optin(monkeypatch: pytest.MonkeyPatch) -> None:
    # Default scan enumerates NO processes: the stub is never even invoked.
    from mcpscan.discovery.process_env import ProcessEnv, ProcessEnvResult

    entry = ProcessEnv(pid=42, proc_name="claude", env=(("ANTHROPIC_API_KEY", _PROC_KEY),))
    called = _stub_process_envs(monkeypatch, ProcessEnvResult(entries=(entry,)))
    report = scan(roots=[], system="Linux", env={}, enumerate_sockets=False)
    assert called == []  # enumerator never touched by default
    assert _process_servers(report) == []


def test_process_env_clean_process_is_not_surfaced(monkeypatch: pytest.MonkeyPatch) -> None:
    # An agent process with no secret in its env yields no server (presence of a
    # running agent is not itself a vulnerability).
    from mcpscan.discovery.process_env import ProcessEnv, ProcessEnvResult

    entry = ProcessEnv(pid=7, proc_name="claude", env=(("LOG_LEVEL", "debug"),))
    _stub_process_envs(monkeypatch, ProcessEnvResult(entries=(entry,)))
    report = scan(
        roots=[], system="Linux", env={}, enumerate_sockets=False, inspect_process_env=True
    )
    assert _process_servers(report) == []


def test_process_env_propagates_inspection_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpscan.discovery.process_env import ProcessEnv, ProcessEnvResult

    entry = ProcessEnv(pid=42, proc_name="claude", env=(("ANTHROPIC_API_KEY", _PROC_KEY),))
    _stub_process_envs(monkeypatch, ProcessEnvResult(entries=(entry,), inspection_incomplete=True))
    report = scan(
        roots=[], system="Linux", env={}, enumerate_sockets=False, inspect_process_env=True
    )
    assert _process_servers(report)[0].inspection_incomplete is True


def test_process_env_raw_secret_never_reaches_json(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpscan.discovery.process_env import ProcessEnv, ProcessEnvResult
    from mcpscan.report.json_report import render_json

    entry = ProcessEnv(pid=42, proc_name="claude", env=(("ANTHROPIC_API_KEY", _PROC_KEY),))
    _stub_process_envs(monkeypatch, ProcessEnvResult(entries=(entry,)))
    report = scan(
        roots=[], system="Linux", env={}, enumerate_sockets=False, inspect_process_env=True
    )
    out = render_json(report)
    assert _PROC_KEY not in out
    assert "CRED-ENV" in out  # the finding IS reported, just redacted


# --- agent-host telemetry / logging health (Wave 3 Feature L; opt-in) ---
_TELE_NOW = 2_000_000_000


def _telemetry_servers(report: object) -> list[object]:
    return [s for s in report.servers if s.id.startswith("telemetry://")]  # type: ignore[attr-defined]


def _claude_log_dir(tmp_path: Path) -> Path:
    log_dir = tmp_path / "Library" / "Logs" / "Claude"
    log_dir.mkdir(parents=True)
    return log_dir


def test_telemetry_absent_dir_flags_absent(tmp_path: Path) -> None:
    # No log directory at all -> logging likely off -> TELEMETRY-ABSENT.
    report = scan(
        roots=[],
        system="Darwin",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_telemetry=True,
        now_epoch=_TELE_NOW,
    )
    servers = _telemetry_servers(report)
    assert len(servers) == 1
    # Separator-agnostic: the id carries host path separators (backslashes on
    # Windows), the surface is the macOS Claude log dir.
    assert servers[0].id.replace("\\", "/").endswith("Library/Logs/Claude")
    assert {f.id for f in servers[0].findings} == {"TELEMETRY-ABSENT"}


def test_telemetry_empty_dir_flags_absent(tmp_path: Path) -> None:
    _claude_log_dir(tmp_path)  # exists but holds no log files
    report = scan(
        roots=[],
        system="Darwin",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_telemetry=True,
        now_epoch=_TELE_NOW,
    )
    servers = _telemetry_servers(report)
    assert {f.id for f in servers[0].findings} == {"TELEMETRY-ABSENT"}


def test_telemetry_fresh_owner_only_log_is_silent(tmp_path: Path) -> None:
    log = _claude_log_dir(tmp_path) / "mcp.log"
    log.write_text("started\n", encoding="utf-8")
    os.utime(log, (_TELE_NOW - 3600, _TELE_NOW - 3600))  # 1h old -> fresh
    if os.name == "posix":
        log.chmod(0o600)
    report = scan(
        roots=[],
        system="Darwin",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_telemetry=True,
        now_epoch=_TELE_NOW,
    )
    assert _telemetry_servers(report) == []


@pytest.mark.skipif(
    os.name != "posix",
    reason="world/group-readable is a POSIX mode concept; Windows chmod is a no-op",
)
def test_telemetry_world_readable_log_flags_perms(tmp_path: Path) -> None:
    log = _claude_log_dir(tmp_path) / "mcp.log"
    log.write_text("entry\n", encoding="utf-8")
    os.utime(log, (_TELE_NOW - 3600, _TELE_NOW - 3600))  # fresh so only perms fire
    log.chmod(0o644)
    report = scan(
        roots=[],
        system="Darwin",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_telemetry=True,
        now_epoch=_TELE_NOW,
    )
    servers = _telemetry_servers(report)
    assert len(servers) == 1
    assert {f.id for f in servers[0].findings} == {"TELEMETRY-PERMS"}


def test_telemetry_stale_log_flags_stale(tmp_path: Path) -> None:
    log = _claude_log_dir(tmp_path) / "mcp.log"
    log.write_text("old\n", encoding="utf-8")
    os.utime(log, (_TELE_NOW - 90 * 86400, _TELE_NOW - 90 * 86400))  # 90 days old
    if os.name == "posix":
        log.chmod(0o600)  # safe perms so only staleness fires
    report = scan(
        roots=[],
        system="Darwin",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_telemetry=True,
        now_epoch=_TELE_NOW,
    )
    servers = _telemetry_servers(report)
    assert {f.id for f in servers[0].findings} == {"TELEMETRY-STALE"}


def test_telemetry_not_read_without_optin(tmp_path: Path) -> None:
    # Default scan reads nothing new: no telemetry server, even with logs absent.
    report = scan(roots=[], system="Darwin", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    assert _telemetry_servers(report) == []


def test_telemetry_absent_finding_does_not_worsen_overall_grade(tmp_path: Path) -> None:
    # A lone LOW telemetry finding grades A and must not drag the overall grade.
    report = scan(
        roots=[],
        system="Darwin",
        env={"HOME": str(tmp_path)},
        enumerate_sockets=False,
        inspect_telemetry=True,
        now_epoch=_TELE_NOW,
    )
    assert report.overall_grade == "A"
