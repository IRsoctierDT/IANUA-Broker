# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Objective F — spend the scanner's time and memory instead of crashing it.

The DoS row of the SPEC §8 threat model reads "huge/pathological config or
socket set hangs the tool", mitigated by size caps and bounded concurrency. Caps
stop the obvious attack; they do not stop the interesting one, which is
**super-linear work on a small input**. A 400 KB file that takes a minute to
process passes every size check on the way in.

Each test here therefore asserts a *time bound*, generously sized so ordinary
CI noise cannot trip it while a genuine complexity regression (an accidental
quadratic in the entropy scorer, a catastrophic-backtracking regex, per-server
work that rescans every other server) blows straight through it.

Wall-clock assertions are a blunt instrument, so the budgets are set at roughly
20x the observed cost rather than at the margin: the goal is to catch an
algorithmic class change, not to benchmark the machine.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from adversarial.corpus import (
    FAKE_ANTHROPIC_KEY,
    deep_json,
    deep_object_json,
    entropy_bomb,
    wide_config,
)
from mcpscan.adapters.claude import ClaudeAdapter
from mcpscan.checks.secrets import shannon_entropy
from mcpscan.engine import scan


def _timed(fn: Callable[[], object]) -> tuple[object, float]:
    start = time.monotonic()
    result = fn()
    return result, time.monotonic() - start


def test_entropy_scoring_is_linear_in_value_length() -> None:
    """A single huge value must not cost quadratic time.

    ``shannon_entropy`` counts occurrences per distinct character; done naively
    (a ``count()`` per character *position* rather than per distinct character)
    a 2 MB value becomes minutes of work. An ``.env`` line is attacker-sized.
    """
    _score, elapsed = _timed(lambda: shannon_entropy(entropy_bomb()))
    assert elapsed < 10.0, f"entropy scoring took {elapsed:.1f}s on a 2 MB value"


def test_entropy_scoring_scales_sub_quadratically() -> None:
    """Doubling the input must not quadruple the time.

    A ratio check is what actually distinguishes "slow machine" from "wrong
    complexity class" — the absolute budget above cannot.
    """
    _a, t_small = _timed(lambda: shannon_entropy(entropy_bomb(200_000)))
    _b, t_large = _timed(lambda: shannon_entropy(entropy_bomb(800_000)))
    # 4x the input; allow 12x the time (linear + noise), reject quadratic (16x+).
    assert t_large < max(t_small * 12, 2.0), f"{t_small:.3f}s -> {t_large:.3f}s for 4x input"


@pytest.mark.parametrize("payload", [deep_json, deep_object_json], ids=["array", "object"])
def test_deep_nesting_is_rejected_quickly(payload: Callable[[], str]) -> None:
    """The recursion guard must trip fast, not after a long climb."""
    _cfg, elapsed = _timed(lambda: ClaudeAdapter().parse("/cfg", payload()))
    assert elapsed < 10.0


def test_many_servers_scale_linearly(tmp_path: Path) -> None:
    """5,000 declared servers must not trigger super-linear cross-server work.

    ``CRED-REUSE`` joins secrets across every server, which is exactly the shape
    that turns into an O(n²) scan if it is written as a nested loop instead of a
    fingerprint index.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(wide_config(), encoding="utf-8")

    report, elapsed = _timed(
        lambda: scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    )
    assert elapsed < 60.0, f"scan of 5,000 servers took {elapsed:.1f}s"
    assert len(report.servers) == 5_000  # type: ignore[attr-defined]


def test_identical_secrets_across_many_servers_stay_bounded(tmp_path: Path) -> None:
    """The blast-radius join is the worst case: one key shared by every server.

    Every server pairs with every other, so a naive implementation produces
    n² findings and a report nobody can read. The check emits one finding per
    involved server instead.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    count = 400
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    f"s{i}": {"command": "x", "env": {"API_KEY": FAKE_ANTHROPIC_KEY}}
                    for i in range(count)
                }
            }
        ),
        encoding="utf-8",
    )
    report, elapsed = _timed(
        lambda: scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    )
    assert elapsed < 30.0
    reuse = [
        f
        for s in report.servers  # type: ignore[attr-defined]
        for f in s.findings
        if f.id == "CRED-REUSE"
    ]
    assert len(reuse) == count  # one per server, not one per pair


def test_a_long_single_line_env_file_is_handled(tmp_path: Path) -> None:
    """One 2 MB ``.env`` line — under the cap, above what a naive scan enjoys."""
    from mcpscan.checks import parse_env_text
    from mcpscan.checks.secrets import check_env_file_secrets

    text = f"API_KEY={entropy_bomb(2_000_000)}"
    parsed, parse_time = _timed(lambda: parse_env_text("/p/.env", text))
    _findings, check_time = _timed(lambda: check_env_file_secrets(parsed))  # type: ignore[arg-type]
    assert parse_time + check_time < 20.0


def test_many_env_lines_are_handled(tmp_path: Path) -> None:
    """50,000 entries, each checked against every provider pattern."""
    from mcpscan.checks import parse_env_text
    from mcpscan.checks.secrets import check_env_file_secrets

    text = "\n".join(f"KEY_{i}=value-{i}" for i in range(50_000))
    parsed = parse_env_text("/p/.env", text)
    _findings, elapsed = _timed(lambda: check_env_file_secrets(parsed))
    assert elapsed < 30.0


def test_provider_patterns_do_not_backtrack_catastrophically() -> None:
    """The built-in catalog must stay linear on adversarial near-misses.

    Each pattern is run against a string engineered to *almost* match it — the
    input shape that makes a backtracking regex explode. The built-in patterns
    are anchored and character-class based, so this is a guard against a future
    pattern (or a data-pack-shaped one) introducing nested quantifiers.
    """
    from mcpscan.datapack import builtin_secret_catalog

    catalog = builtin_secret_catalog()
    near_misses = (
        "sk-ant-" + "A" * 5_000 + "!",
        "sk-" + "A" * 5_000 + "!",
        "ghp_" + "A" * 5_000 + "!",
        "AKIA" + "0" * 5_000 + "!",
        "AIza" + "-" * 5_000 + "!",
        "xoxb-" + "-" * 5_000 + "!",
        "-----BEGIN " + "A " * 2_500 + "PRIVATE KEY",
    )
    for label, pattern in catalog.provider_patterns:
        for candidate in near_misses:
            _match, elapsed = _timed(lambda p=pattern, c=candidate: p.search(c))  # type: ignore[misc]
            assert elapsed < 5.0, f"pattern {label!r} backtracked on a near-miss"


def test_a_deeply_nested_config_does_not_exhaust_memory(tmp_path: Path) -> None:
    """The nesting guard trips before the decoder allocates a deep structure.

    Asserted through the engine so the whole read → parse → audit path is
    covered, not just the adapter in isolation.
    """
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(deep_json(500_000), encoding="utf-8")
    report, elapsed = _timed(
        lambda: scan(roots=[root], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    )
    assert elapsed < 30.0
    assert [f.id for s in report.servers for f in s.findings] == [  # type: ignore[attr-defined]
        "CONFIG-UNREADABLE"
    ]


def test_the_acceptance_ledger_has_its_own_tighter_cap(tmp_path: Path) -> None:
    """The ledger caps at 1 MB, well below ``io_safe``'s 5 MB default.

    An operator-authored file has no reason to be large, and a tighter cap is
    less work to defend.
    """
    from mcpscan.acceptance import load_ledgers

    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcpscan-accept.json").write_text(
        json.dumps({"acceptances": []}) + " " * (1024 * 1024 + 1), encoding="utf-8"
    )
    load = load_ledgers([root])
    assert load.entries == ()
    assert load.warnings and "unreadable acceptance ledger" in load.warnings[0]
