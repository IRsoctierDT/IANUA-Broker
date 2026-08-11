# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the pure domain model (T-102)."""

from __future__ import annotations

import dataclasses

import pytest

from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    Server,
    ServerState,
    Severity,
)


def test_severity_weights_are_ordered() -> None:
    weights = [s.weight for s in Severity]
    assert weights == sorted(weights, reverse=True)
    assert Severity.CRITICAL.weight == 40
    assert Severity.INFO.weight == 0


def test_domain_objects_are_frozen() -> None:
    loc = Location(path="~/x", line=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        loc.line = 2  # type: ignore[misc]


def test_finding_defaults_to_no_secret() -> None:
    f = Finding(
        id="C1",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.CRITICAL,
        title="Plaintext secret",
        location=Location(path="~/.env", line=3),
        remediation="Move it to a secret manager.",
        rationale="Plaintext keys are trivially exfiltrated.",
    )
    assert f.secret is None


def test_server_findings_default_empty() -> None:
    s = Server(
        id="s1",
        bind_addr="127.0.0.1",
        port=8000,
        pid=42,
        proc_name="node",
        state=ServerState.RUNNING,
        running=True,
    )
    assert s.findings == ()
    assert s.inspection_incomplete is False


def test_report_holds_grades() -> None:
    r = Report(
        schema_version="1.0",
        servers=(),
        overall_grade="A",
        dimension_grades={Dimension.EXPOSURE: "A"},
    )
    assert r.overall_grade == "A"
    assert r.generated_with_online is False


def test_no_raw_secret_field_exists_on_finding() -> None:
    # Architectural guarantee R1: a Finding cannot carry a raw secret value.
    field_names = {f.name for f in dataclasses.fields(Finding)}
    assert "secret" in field_names
    assert not {"value", "raw", "plaintext", "secret_value"} & field_names
