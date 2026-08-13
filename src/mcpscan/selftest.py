# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Self-test canary: confirm the scanner's core detections still fire (Feature C).

Report Rec 5 — "test that the detections fire" — turned back on the scanner
itself. A silently-degraded build (a check that quietly started returning
nothing, a refactor that dropped a finding id, a broken adapter) is worse than no
scanner at all: it hands out a clean bill of health over real misconfiguration.

:func:`run_selftest` runs the *real* :func:`mcpscan.engine.scan` over a throwaway
fixture that is deliberately riddled with known-bad config, and confirms each
core finding id still appears. It also exercises the exposure classifier with an
in-memory socket (no real bind). It anchors only on **stable, pre-Wave-3** finding
ids so a healthy scanner never trips it and the canary does not churn as the newer
detections evolve.

Offline and side-effect-free from the caller's view: the fixture lives in a
``tempfile`` directory removed before the function returns, home-dir discovery is
redirected into that sandbox so the caller's real host configs are never read, and
socket enumeration is off — no network is touched.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .checks.exposure import check_socket_exposure
from .discovery.sockets import ListeningSocket
from .engine import scan

# A deliberately-misconfigured project config. Each planted misconfig maps 1:1 to
# a core finding id the healthy scanner must raise (see _EXPECTED_CONFIG_FINDINGS).
# The API key is an obvious synthetic canary — it matches the Anthropic key shape
# so the detector fires, but is not a live credential; the check fingerprints it,
# so no raw value is ever surfaced or printed.
_FIXTURE_MCP_JSON = json.dumps(
    {
        "mcpServers": {
            "selftest-canary": {
                "command": "npx",  # a floating runner -> PIN-UNPINNED when unpinned
                "args": ["-y", "left-pad"],
                "env": {"ANTHROPIC_API_KEY": "sk-ant-selftest-canary-not-a-real-key000"},
                "autoApprove": ["*"],  # wildcard auto-approve -> SCOPE-AUTOAPPROVE-WILDCARD
            }
        },
        "permissions": {"allow": ["Bash(*)"]},  # dangerous grant -> SCOPE-DANGEROUS-ALLOW
    },
    indent=2,
)

# Stable, pre-Wave-3 finding ids, one per planted misconfig above. Anchoring on
# these (never the newer Wave-2/3 ids) keeps the canary steady while the newer
# detections evolve.
_EXPECTED_CONFIG_FINDINGS: tuple[str, ...] = (
    "CRED-PLAINTEXT",  # plaintext provider secret in the server env block
    "SCOPE-DANGEROUS-ALLOW",  # Bash(*) auto-allowed in the permission allow-list
    "SCOPE-AUTOAPPROVE-WILDCARD",  # autoApprove: ["*"]
    "PIN-UNPINNED",  # unpinned `npx -y left-pad`
)

# The exposure surface is exercised separately from the config scan: the
# classifier is a pure function, fed a synthetic wildcard bind.
_EXPOSURE_EXPECTED_ID = "EXPOSE-BIND"


@dataclass(frozen=True)
class CanaryResult:
    """Whether one expected detection fired, and on which surface it was checked."""

    expected_id: str
    surface: str
    present: bool


@dataclass(frozen=True)
class SelfTestReport:
    """The outcome of a self-test run: one :class:`CanaryResult` per expected id."""

    results: tuple[CanaryResult, ...]

    @property
    def ok(self) -> bool:
        """True when every expected detection fired (the scanner looks healthy)."""
        return all(r.present for r in self.results)

    @property
    def missing(self) -> tuple[CanaryResult, ...]:
        """The expected detections that did NOT fire (empty when healthy)."""
        return tuple(r for r in self.results if not r.present)


def _config_scan_ids() -> set[str]:
    """Run the real engine over the throwaway fixture and collect the finding ids.

    The fixture and an empty sandbox home both live under one ``tempfile``
    directory that is removed on exit. ``env`` is pinned to the sandbox home so
    host-config discovery cannot reach the caller's real ``~/.claude`` etc., and
    ``enumerate_sockets`` is off so nothing on the box is probed.
    """
    with tempfile.TemporaryDirectory(prefix="mcpscan-selftest-") as tmp:
        sandbox = Path(tmp)
        project = sandbox / "project"
        project.mkdir()
        (project / ".mcp.json").write_text(_FIXTURE_MCP_JSON, encoding="utf-8")
        home = sandbox / "home"
        home.mkdir()
        report = scan(
            roots=[project],
            env={"HOME": str(home)},
            enumerate_sockets=False,
        )
    return {finding.id for server in report.servers for finding in server.findings}


def _exposure_fires() -> bool:
    """Exercise the exposure classifier with a synthetic wildcard socket.

    No socket is opened: a :class:`ListeningSocket` is constructed in memory and
    fed straight to the pure classifier, so the canary covers the exposure path
    without a real bind.
    """
    sock = ListeningSocket(
        ip="0.0.0.0",  # nosec B104 (classifier input, never bound)
        port=8199,
        pid=None,
        proc_name="mcpscan-selftest",
    )
    return any(finding.id == _EXPOSURE_EXPECTED_ID for finding in check_socket_exposure(sock))


def run_selftest() -> SelfTestReport:
    """Run the scanner against known-bad inputs and report which detections fired.

    Returns a structured :class:`SelfTestReport` — one :class:`CanaryResult` per
    expected finding id, across the config-scan and exposure-classifier surfaces.
    Deterministic and offline: the only writes land in a ``tempfile`` directory
    removed before returning, and no network is touched.
    """
    found = _config_scan_ids()
    results = [
        CanaryResult(expected_id=fid, surface="config-scan", present=fid in found)
        for fid in _EXPECTED_CONFIG_FINDINGS
    ]
    results.append(
        CanaryResult(
            expected_id=_EXPOSURE_EXPECTED_ID,
            surface="exposure-classifier",
            present=_exposure_fires(),
        )
    )
    return SelfTestReport(results=tuple(results))
