# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Objective C — make the report lie.

A report is evidence. The strings inside it — server names, arguments, config
paths, ``.env`` keys — are chosen by whoever wrote the config, and the operator
who reads the output has no way to tell which characters came from the tool and
which came from the file. That gap is the attack:

- **Terminal.** ``\\x1b[2J`` erases the findings printed above it; a cursor-up
  sequence overwrites them; a bare ``\\n`` forges an entire ``▶ server [grade A]``
  row; ``\\r`` rewrites the current line in place. A hostile ``.mcp.json`` in a
  cloned repo therefore chooses what ``mcpscan scan`` appears to say.
- **HTML.** An unescaped ``"><script>`` turns a shareable report into stored XSS
  in the reviewer's browser.
- **JSON / SARIF.** A raw control character or an unescaped quote breaks the
  document a CI job parses — or smuggles an extra key into it.
- **DOT / scheduler units.** Generated text with its own syntax: a quote or a
  newline in the wrong place ends one directive and starts an attacker's.

Every renderer is swept with the same corpus, so a new escape primitive is
tested against all of them at once.
"""

from __future__ import annotations

import json
import plistlib
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from adversarial.corpus import (
    ANSI_CLEAR,
    CARRIAGE_RETURN,
    CONTROL_PAYLOADS,
    DOT_BREAKOUT,
    FORGED_REPORT_LINE,
    HIDDEN_UNICODE_PAYLOADS,
    HTML_BREAKOUT,
    KITCHEN_SINK,
    RENDER_PAYLOADS,
    RTL_OVERRIDE,
    UNIT_FILE_BREAKOUT,
    ZERO_WIDTH_SPACE,
)
from mcpscan.checks.tool_integrity import HIDDEN_CODEPOINTS
from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    SecretFingerprint,
    Server,
    ServerState,
    Severity,
)
from mcpscan.report import RenderOptions, inert_text
from mcpscan.report.html import render_html
from mcpscan.report.json_report import render_json
from mcpscan.report.sarif import render_sarif
from mcpscan.report.terminal import render_terminal

#: Characters that must never reach a terminal verbatim: C0, DEL, C1, and the
#: invisible/bidi set the scanner itself flags as a poisoning primitive.
FORBIDDEN_ON_A_TERMINAL = frozenset(
    {chr(c) for c in range(0x20)}
    | {"\x7f"}
    | {chr(c) for c in range(0x80, 0xA0)}
    | {chr(c) for c in HIDDEN_CODEPOINTS}
)


def _poisoned_report(payload: str) -> Report:
    """A report in which every attacker-influenced string is ``payload``."""
    finding = Finding(
        id="TOOL-AUTOAPPROVE",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.CRITICAL,
        title=f"Server {payload!r} auto-approves everything",
        location=Location(path=f"/repo/{payload}/.mcp.json", line=3),
        remediation=f"Remove {payload}",
        rationale=f"The value {payload} grants every tool",
        secret=SecretFingerprint(masked="ab****yz", sha256_8="deadbeef", length=42),
    )
    server = Server(
        id=f"/repo/.mcp.json#{payload}",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=(finding,),
    )
    return Report(
        schema_version="1.1",
        servers=(server,),
        overall_grade="F",
        dimension_grades={Dimension.TOOL_SCOPE: "F"},
    )


# --- inert_text: the primitive every terminal renderer relies on -------------
@pytest.mark.parametrize("payload", RENDER_PAYLOADS, ids=lambda p: repr(p[:20]))
def test_inert_text_defangs_every_render_payload(payload: str) -> None:
    out = inert_text(payload)
    assert not (set(out) & FORBIDDEN_ON_A_TERMINAL)


def test_inert_text_leaves_ordinary_text_alone() -> None:
    """No false positives: real-world config text passes through byte-identical.

    A renderer that mangles ordinary values is its own kind of broken report.
    """
    for benign in (
        "npx -y @modelcontextprotocol/server-github",
        "/Users/dev/Library/Application Support/Claude/claude_desktop_config.json",
        "C:\\Users\\dev\\.cursor\\mcp.json",
        "サーバー名",  # non-Latin script
        "grüße-server",
        "emoji 🚀 server",
        'quote\'s and "double" and <angle>',
    ):
        assert inert_text(benign) == benign


def test_inert_text_shows_rather_than_hides() -> None:
    """A defanged character is replaced by a visible escape, not dropped.

    Silently deleting the character would hide the tampering — the opposite of
    what a security tool should do with evidence of tampering.
    """
    assert inert_text("a\x1b[2Jb") == "a\\u001b[2Jb"
    assert inert_text(f"a{RTL_OVERRIDE}b") == "a\\u202eb"
    assert "\\u000a" in inert_text(FORGED_REPORT_LINE)


# --- terminal ----------------------------------------------------------------
@pytest.mark.parametrize("payload", RENDER_PAYLOADS, ids=lambda p: repr(p[:20]))
def test_terminal_report_cannot_be_repainted(payload: str) -> None:
    """No control or bidi character survives into terminal output."""
    out = render_terminal(_poisoned_report(payload), RenderOptions())
    stray = set(out) & (FORBIDDEN_ON_A_TERMINAL - {"\n"})
    assert not stray, f"terminal output carries {stray!r} from an attacker-chosen string"


def test_terminal_report_line_count_is_not_attacker_controlled() -> None:
    """A newline in a config value cannot forge an extra report row.

    Line-forgery is the subtlest version of this attack: no escape sequence, no
    scary character — just an extra line that reads exactly like a real one.
    """
    clean = render_terminal(_poisoned_report("plain"), RenderOptions())
    forged = render_terminal(_poisoned_report(FORGED_REPORT_LINE), RenderOptions())
    assert len(forged.splitlines()) == len(clean.splitlines())
    # The text may still appear — defanged, inline — but never as its own row,
    # which is what an operator scanning the left margin would read as real.
    assert not any(line.startswith("▶ totally-safe-server") for line in forged.splitlines())


def test_terminal_severity_label_cannot_be_overwritten() -> None:
    """``\\r`` must not rewrite the CRITICAL line the operator is meant to read."""
    out = render_terminal(_poisoned_report(CARRIAGE_RETURN), RenderOptions())
    assert "\r" not in out
    assert "[CRITICAL" in out


# --- HTML --------------------------------------------------------------------
@pytest.mark.parametrize("payload", RENDER_PAYLOADS, ids=lambda p: repr(p[:20]))
def test_html_report_has_no_injected_markup(payload: str) -> None:
    out = render_html(_poisoned_report(payload), RenderOptions())
    lowered = out.lower()
    # Escaped text (``&quot; onmouseover=&quot;``) is inert and expected; what
    # must never appear is the *syntax* — a real tag or a real attribute quote.
    assert "<script" not in lowered
    assert 'onmouseover="' not in lowered
    assert "javascript:" not in lowered
    assert "<img" not in lowered


def test_html_report_stays_self_contained_under_attack() -> None:
    """ADR-8/NFR-SEC1: no remote reference can be injected into the report.

    An attacker-chosen ``src``/``href`` would turn an offline artifact into a
    beacon that phones home when the reviewer opens it.
    """
    out = render_html(_poisoned_report('"><img src="http://evil.test/x.png">'), RenderOptions())
    assert "<img" not in out
    assert 'src="http' not in out
    assert "&lt;img" in out  # present only as escaped, inert text


def test_html_grade_badge_class_is_not_attacker_controlled() -> None:
    """The one place a value reaches a CSS class must stay escaped."""
    report = _poisoned_report("x")
    report = Report(
        schema_version=report.schema_version,
        servers=report.servers,
        overall_grade='F"><script>alert(1)</script>',
        dimension_grades=report.dimension_grades,
    )
    out = render_html(report, RenderOptions())
    assert "<script>" not in out


# --- JSON / SARIF ------------------------------------------------------------
@pytest.mark.parametrize("payload", RENDER_PAYLOADS, ids=lambda p: repr(p[:20]))
def test_json_report_stays_parseable_and_shape_stable(payload: str) -> None:
    """The machine-readable report survives every payload with its shape intact."""
    raw = render_json(_poisoned_report(payload), RenderOptions())
    parsed = json.loads(raw)
    assert parsed["tool"] == "ianua-broker"
    assert "injected" not in parsed  # no smuggled top-level key
    assert len(parsed["servers"]) == 1
    assert len(parsed["servers"][0]["findings"]) == 1


@pytest.mark.parametrize("payload", CONTROL_PAYLOADS, ids=lambda p: repr(p[:20]))
def test_json_report_escapes_c0_and_round_trips(payload: str) -> None:
    """The machine format keeps fidelity: C0 escaped, value recoverable exactly.

    A raw C0 byte would break strict JSON consumers, so ``json.dumps`` escapes
    it. The machine report deliberately preserves the value verbatim otherwise —
    a consumer needs to see what the config actually said. Making that value
    *safe to print* is the terminal renderer's job (:func:`inert_text`), not the
    JSON encoder's, which is why this asserts round-trip fidelity rather than
    absence of the payload.
    """
    raw = render_json(_poisoned_report(payload), RenderOptions())
    c0_and_del = {chr(c) for c in range(0x20)} | {"\x7f"}
    assert not (set(raw) & (c0_and_del - {"\n"}))
    parsed = json.loads(raw)
    assert payload in parsed["servers"][0]["id"]


@pytest.mark.parametrize("payload", RENDER_PAYLOADS, ids=lambda p: repr(p[:20]))
def test_sarif_stays_valid_json_and_keeps_one_run(payload: str) -> None:
    raw = render_sarif(_poisoned_report(payload), RenderOptions(), base="/repo")
    parsed = json.loads(raw)
    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"]) == 1


def test_sarif_rule_ids_come_from_the_tool_not_the_config() -> None:
    """Rule ids are check identifiers; a config value must never become one.

    A consumer keys suppressions and dashboards off ``ruleId``, so an
    attacker-chosen id would let a config rename its own alert.
    """
    raw = render_sarif(_poisoned_report(KITCHEN_SINK), RenderOptions(), base="/repo")
    parsed = json.loads(raw)
    for result in parsed["runs"][0]["results"]:
        assert result["ruleId"] == "TOOL-AUTOAPPROVE"


# --- generated formats with their own syntax ---------------------------------
def test_dot_graph_quotes_cannot_break_out(tmp_path: Path) -> None:
    """A node label must not be able to add its own DOT statements."""
    from mcpscan.graph.model import AttackGraph, Node, NodeKind
    from mcpscan.graph.render import render_dot_graph

    graph = AttackGraph(
        schema_version="1.0",
        nodes=(Node(id=DOT_BREAKOUT, kind=NodeKind.MCP_SERVER, label=DOT_BREAKOUT),),
    )
    dot = render_dot_graph(graph)
    # One node statement in, one node statement out: the payload's ``"]`` did not
    # close the label and open a second definition.
    statements = [ln for ln in dot.splitlines() if ln.startswith('  "')]
    assert len(statements) == 1
    assert dot.count("digraph") == 1
    # Its quotes survive only in escaped form.
    assert '\\"' in statements[0]


def test_systemd_unit_refuses_a_newline_bearing_path() -> None:
    """A unit file is line-structured, so a newline in a path is directive
    injection — the generator refuses rather than emitting a broken unit.

    ``shlex.quote`` is not enough here: it keeps the newline inside single
    quotes for a *shell*, but systemd ends the ``ExecStart`` line at the newline
    and reads the remainder as further directives.
    """
    from mcpscan.schedule import Cadence, ScheduleError, SchedulePlan, systemd_units

    plan = SchedulePlan(
        invocation=("mcpscan",),
        roots=(UNIT_FILE_BREAKOUT,),
        baseline="/tmp/baseline.json",
        cadence=Cadence.DAILY,
    )
    with pytest.raises(ScheduleError):
        systemd_units(plan)


def test_systemd_unit_escapes_specifier_characters() -> None:
    """``%`` and ``$`` are systemd expansions, not literals — both are doubled."""
    from mcpscan.schedule import Cadence, SchedulePlan, systemd_units

    plan = SchedulePlan(
        invocation=("mcpscan",),
        roots=("/tmp/%h/$HOME/weird",),
        baseline="/tmp/b.json",
        cadence=Cadence.DAILY,
    )
    _timer, service = systemd_units(plan)
    execstart = next(ln for ln in service.splitlines() if ln.startswith("ExecStart="))
    assert "%%h" in execstart and "$$HOME" in execstart
    assert len([ln for ln in service.splitlines() if ln.startswith("ExecStart")]) == 1


def test_launchd_plist_stays_well_formed_under_attack() -> None:
    """plistlib escapes the payload, so no extra key can be smuggled in."""
    from mcpscan.schedule import Cadence, SchedulePlan, launchd_plist

    plan = SchedulePlan(
        invocation=("mcpscan",),
        roots=("/tmp/x</string><key>RunAtLoad</key><true/><string>",),
        baseline="/tmp/b.json",
        cadence=Cadence.DAILY,
    )
    document = plistlib.loads(launchd_plist(plan).encode("utf-8"))
    assert document["RunAtLoad"] is False  # not flipped by the injected markup
    assert set(document) == {"Label", "ProgramArguments", "StartCalendarInterval", "RunAtLoad"}


def test_windows_task_xml_stays_well_formed_under_attack() -> None:
    """ElementTree escapes the payload, so the task keeps exactly one action."""
    from mcpscan.schedule import Cadence, SchedulePlan, windows_task_xml

    plan = SchedulePlan(
        invocation=("mcpscan",),
        roots=("C:\\x</Command><Command>evil.exe",),
        baseline="C:\\b.json",
        cadence=Cadence.DAILY,
    )
    root = ET.fromstring(windows_task_xml(plan))  # nosec B314 - our own generated text
    ns = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
    commands = root.findall(f".//{ns}Exec/{ns}Command")
    assert len(commands) == 1
    assert commands[0].text == "cmd.exe"


# --- the other terminal renderers ---------------------------------------------
def test_drift_render_is_inert(tmp_path: Path) -> None:
    from mcpscan.drift.model import (
        ChangeType,
        Direction,
        DriftCause,
        DriftEntry,
        DriftReport,
        FactKind,
    )
    from mcpscan.drift.render import render_terminal_drift

    entry = DriftEntry(
        change=ChangeType.CHANGED,
        kind=FactKind.SERVER,
        key=KITCHEN_SINK,
        summary=KITCHEN_SINK,
        direction=Direction.REGRESSION,
        cause=DriftCause.CONFIG_DRIFT,
        detail_before=((KITCHEN_SINK, ANSI_CLEAR),),
        detail_after=((KITCHEN_SINK, CARRIAGE_RETURN),),
    )
    out = render_terminal_drift(DriftReport(entries=(entry,)))
    assert not (set(out) & (FORBIDDEN_ON_A_TERMINAL - {"\n"}))


def test_inventory_render_is_inert() -> None:
    from mcpscan.inventory.model import Asset, AssetKind, AssetSource, Confidence, Inventory
    from mcpscan.inventory.render import render_terminal_inventory

    asset = Asset(
        kind=AssetKind.MCP_SERVER,
        product=KITCHEN_SINK,
        source=next(iter(AssetSource)),
        location=KITCHEN_SINK,
        confidence=next(iter(Confidence)),
        evidence=(KITCHEN_SINK,),
        server_name=KITCHEN_SINK,
        proc_name=ANSI_CLEAR,
        pid=1,
    )
    out = render_terminal_inventory(
        Inventory(schema_version="1.0", assets=(asset,)), RenderOptions()
    )
    assert not (set(out) & (FORBIDDEN_ON_A_TERMINAL - {"\n"}))


def test_atlas_render_is_inert() -> None:
    from mcpscan.atlas.render import render_terminal_atlas

    out = render_terminal_atlas(_poisoned_report(KITCHEN_SINK), RenderOptions())
    assert not (set(out) & (FORBIDDEN_ON_A_TERMINAL - {"\n"}))


def test_graph_render_is_inert() -> None:
    from mcpscan.graph.model import AttackGraph, AttackPath, Node, NodeKind
    from mcpscan.graph.render import render_terminal_graph

    node = Node(id=KITCHEN_SINK, kind=NodeKind.MCP_SERVER, label=KITCHEN_SINK)
    path = AttackPath(
        nodes=(node.id,),
        edges=(),
        severity=Severity.CRITICAL,
        summary=KITCHEN_SINK,
        rationale=KITCHEN_SINK,
    )
    graph = AttackGraph(schema_version="1.0", nodes=(node,), paths=(path,))
    out = render_terminal_graph(graph, RenderOptions())
    assert not (set(out) & (FORBIDDEN_ON_A_TERMINAL - {"\n"}))


# --- remote data: the same stance on the other channel ------------------------
@pytest.mark.parametrize(
    "payload", (*CONTROL_PAYLOADS, *HIDDEN_UNICODE_PAYLOADS), ids=lambda p: repr(p[:20])
)
def test_remote_sanitizer_neutralizes_the_same_alphabet(payload: str) -> None:
    """``lan.sanitize_remote`` and the renderers must not disagree.

    A banner is attacker-controlled in exactly the way a cloned config is; if one
    channel strips a bidi override and the other does not, the weaker one is the
    one an attacker uses.
    """
    from mcpscan.lan.sanitize import sanitize_remote

    out = sanitize_remote(f"MCP/1.0 {payload} server")
    assert not (set(out) & FORBIDDEN_ON_A_TERMINAL)
    assert out.startswith("[untrusted remote data]")


def test_remote_sanitizer_caps_length() -> None:
    """An unbounded banner cannot flood the report."""
    from mcpscan.lan.sanitize import sanitize_remote

    out = sanitize_remote("A" * 10_000)
    assert len(out) < 300


def test_hidden_unicode_catalog_is_shared_not_duplicated() -> None:
    """The flagged-as-hidden set and the neutralized set are the same object.

    Two hand-maintained copies would drift, and the drift would be silent: the
    scanner would flag a codepoint in a config while still printing it raw.
    """
    for codepoint in HIDDEN_CODEPOINTS:
        assert inert_text(chr(codepoint)) != chr(codepoint)
    assert ord(ZERO_WIDTH_SPACE) in HIDDEN_CODEPOINTS
    assert ord(RTL_OVERRIDE) in HIDDEN_CODEPOINTS


def test_html_and_terminal_agree_a_finding_exists() -> None:
    """Defanging must not drop the finding, only its dangerous characters."""
    report = _poisoned_report(HTML_BREAKOUT)
    assert "TOOL-AUTOAPPROVE" in render_json(report, RenderOptions())
    assert "auto-approves everything" in render_terminal(report, RenderOptions())
    assert "auto-approves everything" in render_html(report, RenderOptions())
