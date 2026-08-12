"""Credential checks: detection, redaction in findings, and clean fixtures (T-206/207/212)."""

from __future__ import annotations

from dataclasses import replace

from mcpscan.adapters.base import ServerDecl
from mcpscan.checks import parse_env_text
from mcpscan.checks.secrets import (
    check_env_file_secrets,
    check_secret_at_rest,
    check_secret_reuse,
    check_server_env,
    shannon_entropy,
)
from mcpscan.domain import Dimension, Finding, Location, Server, ServerState, Severity
from mcpscan.redaction import fingerprint_secret

ANTHROPIC_KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
OTHER_KEY = "sk-ant-api03-ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"


def test_detects_provider_key_in_server_env() -> None:
    server = ServerDecl(name="x", command="node", env=(("ANTHROPIC_API_KEY", ANTHROPIC_KEY),))
    findings = check_server_env(server, "/cfg.json")
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    # Redaction: the raw key must NOT appear anywhere on the finding.
    fp = findings[0].secret
    assert fp is not None
    assert ANTHROPIC_KEY not in fp.masked
    assert ANTHROPIC_KEY not in repr(findings[0])


def test_clean_server_env_yields_no_findings() -> None:
    # T-212 negative fixture: a non-secret env var must not fire.
    server = ServerDecl(name="x", command="node", env=(("LOG_LEVEL", "debug"),))
    assert check_server_env(server, "/cfg.json") == []


def test_env_file_detection_with_line_numbers() -> None:
    text = "# comment\nLOG=info\nOPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
    findings = check_env_file_secrets(parse_env_text("/.env", text))
    assert len(findings) == 1
    assert findings[0].location.line == 3


def test_at_rest_flags_group_readable_secret() -> None:
    env = parse_env_text("/.env", f"TOKEN={ANTHROPIC_KEY}\n", mode=0o644)
    findings = check_secret_at_rest(env)
    assert any(f.id == "CRED-PERMS" for f in findings)


def test_at_rest_clean_when_no_secret_present() -> None:
    env = parse_env_text("/.env", "LOG=info\n", mode=0o644)
    assert check_secret_at_rest(env) == []


def test_at_rest_flags_git_tracked_secret() -> None:
    # A secret-bearing .env committed to git leaks to anyone with repo access,
    # regardless of its file mode (CRED-GIT is independent of CRED-PERMS).
    env = replace(parse_env_text("/.env", f"TOKEN={ANTHROPIC_KEY}\n", mode=0o600), git_tracked=True)
    findings = check_secret_at_rest(env)
    assert any(f.id == "CRED-GIT" and f.severity is Severity.HIGH for f in findings)
    # 0o600 is not group/world-readable, so CRED-PERMS must NOT also fire.
    assert not any(f.id == "CRED-PERMS" for f in findings)


def test_entropy_monotonic() -> None:
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a8Fk2Lp9Qz")


def test_entropy_of_empty_string_is_zero() -> None:
    assert shannon_entropy("") == 0.0


# --- CRED-REUSE blast radius (Wave 1 Feature C) ---
def _secret_server(server_id: str, path: str, *raws: str) -> Server:
    findings = tuple(
        Finding(
            id="CRED-PLAINTEXT",
            dimension=Dimension.CREDENTIAL,
            severity=Severity.CRITICAL,
            title="Plaintext secret in config",
            location=Location(path=path),
            remediation="Rotate it.",
            rationale="Plaintext credentials are trivially exfiltrated.",
            secret=fingerprint_secret(raw),
        )
        for raw in raws
    )
    return Server(
        id=server_id,
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=findings,
    )


def test_secret_reuse_across_two_servers_flags_both() -> None:
    a = _secret_server("/a.json#one", "/a.json", ANTHROPIC_KEY)
    b = _secret_server("/b.json#two", "/b.json", ANTHROPIC_KEY)
    additions = check_secret_reuse([a, b])
    assert set(additions) == {"/a.json#one", "/b.json#two"}
    finding = additions["/a.json#one"][0]
    assert finding.id == "CRED-REUSE"
    assert finding.dimension is Dimension.CREDENTIAL
    assert finding.severity is Severity.MEDIUM
    assert finding.title == "Secret reused across 2 locations"
    assert finding.location.path == "/a.json"
    # The rationale names the OTHER location by path and the sha256_8 handle.
    assert "/b.json" in finding.rationale
    assert fingerprint_secret(ANTHROPIC_KEY).sha256_8 in finding.rationale
    assert ANTHROPIC_KEY not in repr(finding)  # redaction stance holds
    assert "/a.json" in additions["/b.json#two"][0].rationale


def test_secret_reuse_needs_two_distinct_servers() -> None:
    # Same secret under two env keys on ONE server is duplication, not reuse.
    solo = _secret_server("/a.json#one", "/a.json", ANTHROPIC_KEY, ANTHROPIC_KEY)
    assert check_secret_reuse([solo]) == {}


def test_different_secrets_are_not_reuse() -> None:
    a = _secret_server("/a.json#one", "/a.json", ANTHROPIC_KEY)
    b = _secret_server("/b.json#two", "/b.json", OTHER_KEY)
    assert check_secret_reuse([a, b]) == {}


def test_secret_reuse_counts_every_location() -> None:
    servers = [
        _secret_server("/a.json#a", "/a.json", ANTHROPIC_KEY),
        _secret_server("/b.json#b", "/b.json", ANTHROPIC_KEY),
        _secret_server("/c.json#c", "/c.json", ANTHROPIC_KEY),
    ]
    additions = check_secret_reuse(servers)
    finding = additions["/a.json#a"][0]
    assert finding.title == "Secret reused across 3 locations"
    assert "/b.json, /c.json" in finding.rationale  # others only, sorted
    assert "/a.json" not in finding.rationale  # its own path is the location, not an "other"


def test_secret_reuse_is_deterministic() -> None:
    servers = [
        _secret_server("/b.json#b", "/b.json", ANTHROPIC_KEY, OTHER_KEY),
        _secret_server("/a.json#a", "/a.json", OTHER_KEY, ANTHROPIC_KEY),
    ]
    first = check_secret_reuse(servers)
    assert first == check_secret_reuse(servers)
    # Two shared secrets -> two CRED-REUSE findings per involved server.
    assert [len(v) for v in first.values()] == [2, 2]
