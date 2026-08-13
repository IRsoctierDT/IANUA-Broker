# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Self-test canary (Feature C): the scanner confirming its own detections fire.

Covers the pure :func:`mcpscan.selftest.run_selftest` (healthy vs a monkeypatched,
degraded scanner) and the ``mcpscan selftest`` CLI wiring (exit code + the loud
degraded message).
"""

from __future__ import annotations

import pytest

import mcpscan.engine as engine_mod
import mcpscan.selftest as selftest_mod
from mcpscan.cli import main
from mcpscan.selftest import run_selftest

# The stable core ids the canary anchors on (mirrors selftest._EXPECTED_* + exposure).
_EXPECTED_IDS = {
    "CRED-PLAINTEXT",
    "SCOPE-DANGEROUS-ALLOW",
    "SCOPE-AUTOAPPROVE-WILDCARD",
    "PIN-UNPINNED",
    "EXPOSE-BIND",
}


def test_run_selftest_healthy_reports_every_detection_present() -> None:
    report = run_selftest()
    assert report.ok
    assert report.missing == ()
    assert {r.expected_id for r in report.results} == _EXPECTED_IDS
    assert all(r.present for r in report.results)


def test_run_selftest_covers_both_surfaces() -> None:
    report = run_selftest()
    surfaces = {r.surface for r in report.results}
    assert surfaces == {"config-scan", "exposure-classifier"}
    exposure = next(r for r in report.results if r.expected_id == "EXPOSE-BIND")
    assert exposure.surface == "exposure-classifier"


def test_run_selftest_is_deterministic() -> None:
    first = run_selftest()
    second = run_selftest()
    assert first == second


def test_run_selftest_detects_a_degraded_config_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate a silently-broken secret check: the engine resolves check_server_env
    # from its own module globals at call time, so patching it here degrades the
    # real scan the canary runs.
    monkeypatch.setattr(engine_mod, "check_server_env", lambda *_a, **_k: [])
    report = run_selftest()
    assert not report.ok
    missing_ids = {r.expected_id for r in report.missing}
    assert missing_ids == {"CRED-PLAINTEXT"}
    # The other detections still fire — only the sabotaged one goes missing.
    still_present = {r.expected_id for r in report.results if r.present}
    assert still_present == _EXPECTED_IDS - {"CRED-PLAINTEXT"}


def test_run_selftest_detects_a_degraded_exposure_classifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(selftest_mod, "check_socket_exposure", lambda _sock: [])
    report = run_selftest()
    assert not report.ok
    assert {r.expected_id for r in report.missing} == {"EXPOSE-BIND"}


def test_cli_selftest_healthy_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["selftest"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "selftest OK" in out
    for finding_id in _EXPECTED_IDS:
        assert finding_id in out  # every checked id is listed
    assert out.count("[PASS]") == len(_EXPECTED_IDS)
    assert "[FAIL]" not in out


def test_cli_selftest_degraded_exits_nonzero_and_is_loud(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(engine_mod, "check_server_pinning", lambda *_a, **_k: [])
    rc = main(["selftest"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "[FAIL]" in captured.out
    assert "scanner appears degraded" in captured.err
    assert "PIN-UNPINNED" in captured.err
