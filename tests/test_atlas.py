# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Tier-2 atlas: mapping-table completeness, citation hygiene, rendering."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from mcpscan.atlas import MAPPINGS, Framework, framework_label, refs_for
from mcpscan.atlas.render import (
    render_json_atlas,
    render_terminal_atlas,
    render_terminal_matrix,
)
from mcpscan.domain import Finding, Report
from mcpscan.report import RenderOptions

_SRC = Path(__file__).resolve().parents[1] / "src" / "mcpscan"
# Findings are constructed only in the checks and the lan runner; other packages
# (e.g. trust relationships) also use ``id=`` but those are not scanner findings.
_FINDING_SOURCES = (_SRC / "checks", _SRC / "lan")


def _emittable_check_ids() -> set[str]:
    """Every finding id the source tree can emit (the ground truth to cover)."""
    ids: set[str] = set()
    for source in _FINDING_SOURCES:
        for path in source.rglob("*.py"):
            ids.update(re.findall(r'id="([A-Z][A-Z0-9-]+)"', path.read_text(encoding="utf-8")))
    return ids


# --- completeness: the table must track the source, both directions ---
def test_every_emittable_finding_id_is_mapped() -> None:
    unmapped = _emittable_check_ids() - set(MAPPINGS)
    assert unmapped == set(), f"finding id(s) with no atlas mapping: {sorted(unmapped)}"


def test_no_stale_mapping_for_a_removed_check() -> None:
    stale = set(MAPPINGS) - _emittable_check_ids()
    assert stale == set(), f"atlas maps finding id(s) no check emits: {sorted(stale)}"


def test_every_check_has_attack_and_at_least_three_citations() -> None:
    for check_id, refs in MAPPINGS.items():
        frameworks = {r.framework for r in refs}
        assert Framework.ATTACK in frameworks, f"{check_id}: missing an ATT&CK citation"
        assert len(refs) >= 3, f"{check_id}: fewer than 3 citations"


# --- citation hygiene: every ref id matches its framework's format ---
_REF_FORMATS: dict[Framework, str] = {
    Framework.ATTACK: r"^T\d{4}(\.\d{3})?$",
    Framework.ATLAS: r"^AML\.T\d{4}$",
    Framework.OWASP_LLM: r"^LLM\d{2}$",
    Framework.NIST_AI_RMF: r"^(GOVERN|MAP|MEASURE|MANAGE)$",
    Framework.CIS: r"^Control \d{1,2}$",
}


def test_ref_ids_match_their_framework_format() -> None:
    for check_id, refs in MAPPINGS.items():
        for ref in refs:
            pattern = _REF_FORMATS[ref.framework]
            assert re.match(pattern, ref.ref), (
                f"{check_id}: ref {ref.ref!r} does not match the "
                f"{framework_label(ref.framework)} id format {pattern}"
            )


def test_every_ref_has_a_title_and_label() -> None:
    for refs in MAPPINGS.values():
        for ref in refs:
            assert ref.title.strip()
            assert framework_label(ref.framework)


def test_unknown_check_id_fails_soft() -> None:
    assert refs_for("NOT-A-CHECK") == ()


# --- rendering ---
def test_matrix_render_lists_every_check() -> None:
    out = render_terminal_matrix()
    for check_id in MAPPINGS:
        assert check_id in out
    assert "MITRE ATT&CK" in out and "CIS Controls v8" in out


def test_terminal_atlas_annotates_findings(
    make_report: Callable[..., Report], make_finding: Callable[..., Finding]
) -> None:
    report = make_report(make_finding(id="CRED-PLAINTEXT"))
    out = render_terminal_atlas(report, RenderOptions())
    assert "1 finding(s) mapped" in out
    assert "CRED-PLAINTEXT" in out
    assert "T1552.001" in out and "AML.T0055" in out  # citations present


def test_terminal_atlas_clean_report(make_report: Callable[..., Report]) -> None:
    out = render_terminal_atlas(make_report(), RenderOptions())
    assert "No findings" in out


def test_terminal_atlas_handles_unmapped_id(
    make_report: Callable[..., Report], make_finding: Callable[..., Finding]
) -> None:
    report = make_report(make_finding(id="X-FUTURE-CHECK"))
    out = render_terminal_atlas(report, RenderOptions())
    assert "no framework mapping" in out  # degrades visibly, never crashes


def test_json_atlas_is_stable_and_complete(
    make_report: Callable[..., Report], make_finding: Callable[..., Finding]
) -> None:
    report = make_report(make_finding(id="PIN-UNPINNED"))
    first = render_json_atlas(report, RenderOptions())
    assert first == render_json_atlas(report, RenderOptions())  # byte-stable
    payload = json.loads(first)
    assert payload["schema_version"] == "1.0"
    finding = payload["findings"][0]
    assert finding["id"] == "PIN-UNPINNED"
    assert any(m["ref"] == "AML.T0010" for m in finding["mappings"])
    # The full matrix rides along for reference consumers.
    assert set(payload["matrix"]) == set(MAPPINGS)


def test_json_atlas_never_contains_raw_secret(
    make_report: Callable[..., Report], make_finding: Callable[..., Finding]
) -> None:
    # The atlas view carries id/title/location only — no secret field at all.
    report = make_report(make_finding(id="CRED-PLAINTEXT"))
    payload = json.loads(render_json_atlas(report, RenderOptions()))
    assert "secret" not in json.dumps(payload["findings"])


def test_terminal_atlas_skips_findingless_servers(
    make_report: Callable[..., Report], make_finding: Callable[..., Finding]
) -> None:
    from dataclasses import replace

    base = make_report(make_finding(id="CRED-PLAINTEXT"))
    clean = replace(base.servers[0], id="clean#server", findings=())
    report = replace(base, servers=(clean, *base.servers))
    out = render_terminal_atlas(report, RenderOptions())
    assert "clean#server" not in out
