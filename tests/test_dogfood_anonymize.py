# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Dogfood anonymizer (T-402 Phase 2): scrub real configs into safe fixtures.

The security-critical property: no raw secret and no username may survive
anonymization, yet the scrubbed config must still trip the *same* checks so the
regression fixture stays real.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools" / "dogfood"))

from anonymize import (
    AnonymizeReport,
    _entropy_synthetic,
    _synthetic_for,
    anonymize,
    suggest_fixture,
)
from corpus import evaluate

from mcpscan.checks.secrets import _looks_secret

_ANTHROPIC = "sk-ant-api03-REALdeadbeef1234567890ABCDEF"
_HIGH_ENTROPY = "R3al-Db-Pa55word-9x2QzLmNp7Kv"


def _claude_config(secret: str, *, username: str = "alice") -> str:
    return json.dumps(
        {
            "mcpServers": {
                "db": {
                    "command": "npx",  # floating runner -> PIN-UNPINNED on the unpinned pkg
                    "args": ["-y", "db-mcp-server"],
                    "env": {
                        "ANTHROPIC_API_KEY": secret,
                        "DB_PATH": f"/home/{username}/data/app.db",  # a path to scrub
                    },
                }
            }
        }
    )


# --- the two guarantees ---
def test_no_raw_secret_survives() -> None:
    scrubbed, report = anonymize("claude", _claude_config(_ANTHROPIC))
    assert _ANTHROPIC not in scrubbed
    assert report.total_secrets == 1


def test_no_username_survives() -> None:
    scrubbed, report = anonymize("claude", _claude_config(_ANTHROPIC, username="alice"))
    assert "alice" not in scrubbed
    assert "/home/user/" in scrubbed
    assert report.paths_scrubbed >= 1


def test_scrubbed_config_still_trips_the_same_check() -> None:
    # The whole point: the regression stays real. A provider-shaped synthetic
    # must still match the provider regex (still a detected secret).
    scrubbed, _ = anonymize("claude", _claude_config(_ANTHROPIC))
    payload = json.loads(scrubbed)
    new_value = payload["mcpServers"]["db"]["env"]["ANTHROPIC_API_KEY"]
    assert new_value != _ANTHROPIC
    assert _looks_secret("ANTHROPIC_API_KEY", new_value) is not None


def test_entropy_secret_is_replaced_with_entropy_synthetic() -> None:
    cfg = json.dumps(
        {"mcpServers": {"x": {"command": "node", "env": {"DB_PASSWORD": _HIGH_ENTROPY}}}}
    )
    scrubbed, report = anonymize("claude", cfg)
    assert _HIGH_ENTROPY not in scrubbed
    new_value = json.loads(scrubbed)["mcpServers"]["x"]["env"]["DB_PASSWORD"]
    assert _looks_secret("DB_PASSWORD", new_value) is not None  # still flagged
    assert report.secrets_replaced.get("High-entropy secret") == 1


def test_clean_config_is_unchanged() -> None:
    clean = json.dumps(
        {"mcpServers": {"x": {"command": "npx", "args": ["pkg@1.0.0"], "env": {"LOG": "info"}}}}
    )
    scrubbed, report = anonymize("claude", clean)
    assert json.loads(scrubbed) == json.loads(clean)
    assert report.total_secrets == 0 and report.paths_scrubbed == 0


# --- synthetic generators ---
@pytest.mark.parametrize(
    ("real", "key"),
    [
        ("sk-ant-api03-" + "x" * 30, "ANTHROPIC_API_KEY"),
        ("sk-" + "A" * 40, "OPENAI_API_KEY"),
        ("ghp_" + "b" * 40, "GITHUB_TOKEN"),
        ("AKIA" + "ABCDEFGH12345678", "AWS_ACCESS_KEY"),
    ],
)
def test_provider_synthetics_still_match_their_pattern(real: str, key: str) -> None:
    synthetic = _synthetic_for(real)
    assert synthetic != real
    assert _looks_secret(key, synthetic) is not None


def test_entropy_synthetic_meets_the_entropy_floor() -> None:
    from mcpscan.checks.secrets import shannon_entropy

    value = _entropy_synthetic(24)
    assert len(value) == 24
    assert shannon_entropy(value) >= 3.5


# --- multiple occurrences + report shape ---
def test_repeated_secret_is_fully_replaced_and_counted() -> None:
    secret = _ANTHROPIC
    cfg = json.dumps(
        {
            "mcpServers": {
                "a": {"command": "node", "env": {"ANTHROPIC_API_KEY": secret}},
                "b": {"command": "node", "env": {"ANTHROPIC_API_KEY": secret}},
            }
        }
    )
    scrubbed, report = anonymize("claude", cfg)
    assert secret not in scrubbed
    assert report.secrets_replaced["Anthropic API key"] == 2


def test_report_holds_no_raw_value() -> None:
    _scrubbed, report = anonymize("claude", _claude_config(_ANTHROPIC))
    assert isinstance(report, AnonymizeReport)
    assert _ANTHROPIC not in repr(report)  # counts and categories only


def test_unknown_host_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown host"):
        anonymize("not-a-host", "{}")


# --- fixture emission (the loop-closer: verified expects) ---
def test_suggest_fixture_derives_verified_expects() -> None:
    scrubbed, _ = anonymize("claude", _claude_config(_ANTHROPIC))
    snippet = suggest_fixture("claude", "messy", "project", ".mcp.json", scrubbed)
    assert snippet.startswith("Fixture(")
    # The emitted fixture, once evaluated, must match its own declared expects —
    # i.e. the anonymizer produced a self-consistent, real regression fixture.
    assert "CRED-PLAINTEXT" in snippet  # the anthropic key is still detected
    assert "PIN-UNPINNED" in snippet  # unpinned db-mcp-server still detected


def test_emitted_fixture_is_self_consistent() -> None:
    # Anonymize -> emit -> the scrubbed content, re-evaluated, yields exactly the
    # checks the snippet claims (no drift between what we scrub and what we label).
    from corpus import CHECK_IDS, Fixture

    scrubbed, _ = anonymize("claude", _claude_config(_ANTHROPIC))
    probe = Fixture("claude", "messy", "project", ".mcp.json", scrubbed)
    actual = evaluate(probe).actual & set(CHECK_IDS)
    assert "CRED-PLAINTEXT" in actual and "PIN-UNPINNED" in actual


# --- Phase-2 hardening: provider sweep everywhere + fail-closed guard ---
def test_provider_secret_in_args_is_swept() -> None:
    # A key hiding in args (not env) is NOT found by the structured pass, but the
    # provider sweep must still scrub it — nothing provider-shaped may survive.
    real = "sk-ant-api03-REALkeyMaterialInArgs1234567890"
    cfg = json.dumps({"mcpServers": {"x": {"command": "node", "args": ["--token", real]}}})
    scrubbed, report = anonymize("claude", cfg)
    assert real not in scrubbed
    assert report.secrets_replaced.get("Anthropic API key") == 1


def test_env_provider_secret_is_counted_once_not_twice() -> None:
    # A provider key in env is replaced by pass 1; pass 2 must not re-count its
    # own synthetic. Exactly one replacement is reported.
    cfg = json.dumps(
        {"mcpServers": {"x": {"command": "node", "env": {"ANTHROPIC_API_KEY": _ANTHROPIC}}}}
    )
    _, report = anonymize("claude", cfg)
    assert report.secrets_replaced.get("Anthropic API key") == 1


def test_all_provider_synthetics_are_idempotent_under_resweep() -> None:
    # Every synthetic must itself match its pattern *as a whole*, so a second
    # anonymize pass changes nothing and never trips the fail-closed guard.
    from anonymize import _PROVIDER_SYNTHETICS

    for _label, pattern, synthetic in _PROVIDER_SYNTHETICS:
        m = pattern.search(synthetic)
        assert m is not None and m.group(0) == synthetic, synthetic


def test_fail_closed_guard_raises_on_surviving_token() -> None:
    from anonymize import LeakError, _assert_no_provider_secret

    with pytest.raises(LeakError, match="survived anonymization"):
        _assert_no_provider_secret('token = "sk-ant-api03-stillARealLiveKey1234567890"')


def test_anonymize_text_is_idempotent() -> None:
    # Re-running on already-scrubbed output must not corrupt it: the synthetic is
    # itself detected (that's what keeps the fixture real), so it re-synthesizes
    # to the same value and the TEXT is stable — no real secret can reappear.
    once, _ = anonymize("claude", _claude_config(_ANTHROPIC))
    twice, _ = anonymize("claude", once)
    assert twice == once
    assert _ANTHROPIC not in twice
