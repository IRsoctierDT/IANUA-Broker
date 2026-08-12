"""Running-process env enumeration + CRED-ENV secret check (Wave 2 Feature G).

The psutil edge is exercised through a fake module (mirroring the socket tests'
``fake_psutil``); the check itself is pure over ``ProcessEnv`` inputs. The scope
guardrail (only agent/MCP processes) and the redaction stance (raw value never on
a finding) are asserted directly.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from mcpscan.checks.secrets import check_process_env_secrets
from mcpscan.discovery import process_env
from mcpscan.discovery.process_env import (
    ProcessEnv,
    ProcessEnvResult,
    iter_agent_process_envs,
    looks_like_agent,
)
from mcpscan.domain import Dimension, Severity

_FAKE_KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


# --- shared fake psutil exception hierarchy (matches real psutil layout) ---
class _Error(Exception):
    pass


class _AccessDenied(_Error):
    pass


class _NoSuchProcess(_Error):
    def __init__(self, pid: int | None = None) -> None:
        super().__init__(pid)


class _FakeProc:
    """A stand-in for ``psutil.Process`` with per-call denial hooks."""

    def __init__(
        self,
        pid: int,
        name: str,
        cmdline: list[str],
        environ: dict[str, str],
        *,
        deny_env: bool = False,
        dead_name: bool = False,
        env_read_log: list[int] | None = None,
    ) -> None:
        self._pid = pid
        self._name = name
        self._cmdline = cmdline
        self._environ = environ
        self._deny_env = deny_env
        self._dead_name = dead_name
        self._env_read_log = env_read_log

    @property
    def pid(self) -> int:
        return self._pid

    def name(self) -> str:
        if self._dead_name:
            raise _NoSuchProcess(self._pid)
        return self._name

    def cmdline(self) -> list[str]:
        return list(self._cmdline)

    def environ(self) -> dict[str, str]:
        if self._env_read_log is not None:
            self._env_read_log.append(self._pid)
        if self._deny_env:
            raise _AccessDenied()
        return dict(self._environ)


def _fake_psutil(procs: list[_FakeProc], *, iter_raises: bool = False) -> types.ModuleType:
    mod = types.ModuleType("psutil")
    mod.Error = _Error  # type: ignore[attr-defined]
    mod.AccessDenied = _AccessDenied  # type: ignore[attr-defined]
    mod.NoSuchProcess = _NoSuchProcess  # type: ignore[attr-defined]

    def process_iter(attrs: Any = None, ad_value: Any = None) -> list[_FakeProc]:
        if iter_raises:
            raise _Error()
        return procs

    mod.process_iter = process_iter  # type: ignore[attr-defined]
    return mod


def _install(monkeypatch: pytest.MonkeyPatch, mod: types.ModuleType) -> None:
    monkeypatch.setitem(sys.modules, "psutil", mod)


# --- looks_like_agent (scope guardrail) ---
def test_agent_markers_match() -> None:
    assert looks_like_agent("node /usr/lib/some-mcp-server/index.js")
    assert looks_like_agent("npx -y @modelcontextprotocol/server-filesystem")
    assert looks_like_agent("/Applications/Claude.app/Contents/MacOS/Claude")
    assert looks_like_agent("Cursor Helper (Renderer)")


def test_non_agent_processes_do_not_match() -> None:
    # A bare runtime with no agent marker must be skipped (never env-scanned).
    assert not looks_like_agent("python /home/u/train.py")
    assert not looks_like_agent("node /srv/webapp/server.js")
    assert not looks_like_agent("/usr/sbin/sshd -D")


def test_markers_do_not_fire_on_coincidental_substrings() -> None:
    # The guardrail is a privacy boundary: a short marker must NOT match a
    # coincidental substring of an unrelated word, or a non-agent process's
    # environment would be read. "zed" in authorized/synchronized, "cursor"
    # in precursor, "cline" in decline/incline, "mcp" inside a random token.
    assert not looks_like_agent("/usr/lib/systemd/systemd-authorized --flag")
    assert not looks_like_agent("python /opt/pipeline/synchronized_worker.py")
    assert not looks_like_agent("/usr/bin/precursor-daemon")
    assert not looks_like_agent("node /srv/decline-handler/index.js")
    assert not looks_like_agent("/usr/bin/organized")
    assert not looks_like_agent("some-random-mcpx-tool")  # 'mcp' not at a boundary


def test_markers_still_match_at_real_boundaries() -> None:
    # Hyphen/slash/dot/space separators in real package and app names are
    # non-word characters, so bounded markers still match after the fix.
    assert looks_like_agent("uvx mcp-server-git")
    assert looks_like_agent("npx -y @modelcontextprotocol/server-filesystem")
    assert looks_like_agent("/Applications/Claude.app/Contents/MacOS/Claude")
    assert looks_like_agent("/opt/zed/bin/zed --foreground")
    assert looks_like_agent("cline-host --stdio")


# --- iter_agent_process_envs (thin psutil edge) ---
def test_enumerates_agent_process_env(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = _FakeProc(
        321, "claude", ["claude", "mcp"], {"ANTHROPIC_API_KEY": _FAKE_KEY, "PATH": "/usr/bin"}
    )
    _install(monkeypatch, _fake_psutil([proc]))
    result = iter_agent_process_envs(looks_like_agent)
    assert result.inspection_incomplete is False
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.pid == 321
    assert entry.proc_name == "claude"
    assert ("ANTHROPIC_API_KEY", _FAKE_KEY) in entry.env


def test_non_agent_env_is_never_read(monkeypatch: pytest.MonkeyPatch) -> None:
    # The guardrail must gate BEFORE environ() — a non-agent process's env is
    # never touched, even though it holds a "secret".
    read_log: list[int] = []
    agent = _FakeProc(1, "claude", ["claude"], {"K": "v"}, env_read_log=read_log)
    other = _FakeProc(
        2, "python", ["python", "train.py"], {"OPENAI_API_KEY": _FAKE_KEY}, env_read_log=read_log
    )
    _install(monkeypatch, _fake_psutil([agent, other]))
    result = iter_agent_process_envs(looks_like_agent)
    assert read_log == [1]  # only the agent's env was read
    assert [e.pid for e in result.entries] == [1]


def test_access_denied_on_env_marks_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    # Another user's process (or a hardened one) denies environ(): skip it and
    # flag the sweep incomplete, never raise.
    denied = _FakeProc(9, "cursor", ["cursor"], {"K": _FAKE_KEY}, deny_env=True)
    _install(monkeypatch, _fake_psutil([denied]))
    result = iter_agent_process_envs(looks_like_agent)
    assert result.entries == ()
    assert result.inspection_incomplete is True


def test_process_exiting_midscan_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    dead = _FakeProc(9, "claude", ["claude"], {}, dead_name=True)
    live = _FakeProc(10, "cursor", ["cursor"], {"ANTHROPIC_API_KEY": _FAKE_KEY})
    _install(monkeypatch, _fake_psutil([dead, live]))
    result = iter_agent_process_envs(looks_like_agent)
    assert [e.pid for e in result.entries] == [10]
    assert result.inspection_incomplete is True  # the dead one degraded the sweep


def test_process_iter_failure_degrades_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _fake_psutil([], iter_raises=True))
    result = iter_agent_process_envs(looks_like_agent)
    assert result == ProcessEnvResult(entries=(), inspection_incomplete=True)


def test_missing_psutil_degrades_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # No psutil installed at all: empty, flagged incomplete, never raises.
    monkeypatch.setitem(sys.modules, "psutil", None)
    result = iter_agent_process_envs(looks_like_agent)
    assert result == ProcessEnvResult(entries=(), inspection_incomplete=True)


def test_custom_predicate_is_honored(monkeypatch: pytest.MonkeyPatch) -> None:
    # The predicate is injected, not hardcoded: a caller can narrow the scope.
    a = _FakeProc(1, "claude", ["claude"], {"ANTHROPIC_API_KEY": _FAKE_KEY})
    b = _FakeProc(2, "cursor", ["cursor"], {"ANTHROPIC_API_KEY": _FAKE_KEY})
    _install(monkeypatch, _fake_psutil([a, b]))
    result = iter_agent_process_envs(lambda text: "cursor" in text.lower())
    assert [e.pid for e in result.entries] == [2]


# --- check_process_env_secrets (pure) ---
def test_check_flags_secret_with_redacted_fingerprint() -> None:
    entry = ProcessEnv(
        pid=777, proc_name="claude", env=(("ANTHROPIC_API_KEY", _FAKE_KEY), ("HOME", "/home/u"))
    )
    findings = check_process_env_secrets([entry])
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "CRED-ENV"
    assert f.dimension is Dimension.CREDENTIAL
    assert f.severity is Severity.HIGH
    assert f.location.path == "process://claude[777]"
    assert "process env" in f.title
    # Redaction: the raw value never appears on the finding.
    assert f.secret is not None
    assert _FAKE_KEY not in f.secret.masked
    assert _FAKE_KEY not in repr(f)


def test_check_clean_env_yields_nothing() -> None:
    entry = ProcessEnv(pid=1, proc_name="claude", env=(("LOG_LEVEL", "debug"), ("HOME", "/home/u")))
    assert check_process_env_secrets([entry]) == []


def test_check_empty_input_is_empty() -> None:
    assert check_process_env_secrets([]) == []


def test_check_covers_every_process(monkeypatch: pytest.MonkeyPatch) -> None:
    a = ProcessEnv(pid=1, proc_name="claude", env=(("ANTHROPIC_API_KEY", _FAKE_KEY),))
    b = ProcessEnv(pid=2, proc_name="cursor", env=(("OPENAI_API_KEY", "sk-" + "A" * 30),))
    findings = check_process_env_secrets([a, b])
    assert {f.location.path for f in findings} == {"process://claude[1]", "process://cursor[2]"}


def test_module_default_predicate_is_looks_like_agent() -> None:
    # The engine wires this exact predicate; keep the export stable.
    assert process_env.looks_like_agent is looks_like_agent
