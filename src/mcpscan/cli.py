# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for AI Agentic MCPscan (``mcpscan``).

Wires the scan engine to the renderers. Honors the spec's trust properties:
offline by default, secrets redacted unless ``--show-secrets``, and — advise-only
by default — the only file writes are the reports the user explicitly requests
(``--json`` / ``--html`` / ``--sarif``) plus the config edits of opt-in ``--fix``.

Commands: ``scan`` (localhost posture, the default surface), ``inventory``
(classified AI/MCP asset list — observes, never judges; see ``mcpscan.inventory``),
``atlas`` (the same findings mapped to security frameworks; see ``mcpscan.atlas``),
``trust`` (a per-agent Trust Score and the risky factor combinations; see
``mcpscan.trust``), ``baseline`` / ``diff`` (a posture snapshot and drift against
it; see ``mcpscan.drift``), and ``lan`` (authorized network assessment — inert
without a signed manifest; see ``mcpscan.lan``).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__
from .domain import Report, Severity

if TYPE_CHECKING:
    from .drift import Snapshot

_THRESHOLDS = {
    "critical": (Severity.CRITICAL,),
    "high": (Severity.CRITICAL, Severity.HIGH),
    "medium": (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM),
    "low": (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW),
}


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcpscan",
        description=(
            "Local-first, offline-by-default security posture scanner for MCP / local-agent setups."
        ),
    )
    parser.add_argument("--version", action="version", version=f"mcpscan {__version__}")
    parser.add_argument(
        "command",
        nargs="?",
        default=None,
        choices=["scan", "inventory", "atlas", "trust", "baseline", "diff", "lan"],
        help=(
            "The action to run: 'scan' (localhost posture), 'inventory' (classified "
            "AI/MCP asset list), 'atlas' (findings mapped to security frameworks), "
            "'trust' (per-agent Trust Score + risk relationships), 'baseline' (write "
            "a posture snapshot), 'diff' (drift vs a baseline), or 'lan' (authorized "
            "network assessment)."
        ),
    )
    parser.add_argument(
        "--root",
        action="append",
        type=Path,
        metavar="DIR",
        help="Project root to scan for .mcp.json/.env (repeatable; default: cwd).",
    )
    parser.add_argument("--json", metavar="PATH", type=Path, help="Write a JSON report.")
    parser.add_argument("--html", metavar="PATH", type=Path, help="Write an HTML report.")
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        type=Path,
        help="Write a SARIF 2.1.0 report for GitHub code scanning.",
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Reveal masked (first-2/last-2) secret values. Off by default.",
    )
    parser.add_argument(
        "--absolute-paths",
        action="store_true",
        help="Show full paths instead of relativizing to ~ (off by default).",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(_THRESHOLDS),
        default="high",
        help="Minimum severity that makes the command exit non-zero (default: high).",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help=(
            "Enrich pinned packages with OSV advisories. Makes outbound requests "
            "to api.osv.dev (sends only package name+version). Off by default."
        ),
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help=(
            "Apply safe, reversible remediations to discovered configs: remove "
            "dangerous/wildcard entries from permission allow-lists and autoApprove. "
            "Backs up each file to <path>.mcpscan.bak first. Off by default "
            "(the tool is advise-only unless you pass --fix)."
        ),
    )

    drift = parser.add_argument_group(
        "drift", "Baseline & drift (used only with 'baseline' / 'diff')."
    )
    drift.add_argument(
        "--out",
        metavar="PATH",
        type=Path,
        help="baseline: write the snapshot here (default: stdout).",
    )
    drift.add_argument(
        "--baseline",
        metavar="PATH",
        type=Path,
        help="diff: the baseline snapshot to compare the current posture against.",
    )
    drift.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="diff: exit non-zero if any change is a posture regression.",
    )
    drift.add_argument(
        "--max-age-days",
        metavar="N",
        type=int,
        default=30,
        help="diff: baseline age (days) beyond which it counts as stale (default: 30).",
    )
    drift.add_argument(
        "--fail-on-stale",
        action="store_true",
        help=(
            "diff: exit non-zero when the baseline is older than --max-age-days "
            "(explicit opt-in; without it a stale baseline only warns)."
        ),
    )
    drift.add_argument(
        "--no-inventory",
        action="store_true",
        help="baseline/diff: snapshot posture only, skipping the AI/MCP asset inventory.",
    )

    atlas = parser.add_argument_group(
        "atlas", "Framework mapping (used only with the 'atlas' command)."
    )
    atlas.add_argument(
        "--matrix",
        action="store_true",
        help=(
            "atlas: print the full check-id → framework reference matrix without running a scan."
        ),
    )

    trust = parser.add_argument_group(
        "trust", "Agent trust analysis (used only with the 'trust' command)."
    )
    trust.add_argument(
        "--min-grade",
        choices=("A", "B", "C", "D", "F"),
        help="trust: exit non-zero if any agent tool grades below this Trust grade.",
    )

    inventory = parser.add_argument_group(
        "inventory", "AI/MCP asset inventory (used only with the 'inventory' command)."
    )
    inventory.add_argument(
        "--no-probe",
        action="store_true",
        help=(
            "inventory: skip the loopback endpoint fingerprinting; classify from "
            "process names and default ports only."
        ),
    )

    lan = parser.add_argument_group(
        "lan", "Authorized network assessment (used only with the 'lan' command)."
    )
    lan.add_argument(
        "--manifest", metavar="PATH", type=Path, help="Signed TOML authorization manifest."
    )
    lan.add_argument(
        "--signature",
        metavar="PATH",
        type=Path,
        help="Detached signature over the manifest (default: <manifest>.sig).",
    )
    lan.add_argument(
        "--allowed-signers",
        metavar="PATH",
        type=Path,
        help="OpenSSH allowed-signers file for the 'ssh' scheme.",
    )
    lan.add_argument(
        "--invoker",
        choices=("human", "agent"),
        help="Invocation mode. 'agent' gets tighter budgets and exact-host-only scope.",
    )
    lan.add_argument(
        "--dry-run",
        action="store_true",
        help="lan: verify the manifest and print the target plan without sending any packet.",
    )
    lan.add_argument(
        "--enterprise-policy",
        metavar="PATH",
        type=Path,
        help=(
            "lan: TOML policy naming the public (non-private) targets an organization "
            "has authorized. Required to probe any public address."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "lan":
        return _run_lan(args)
    if args.command == "inventory":
        return _run_inventory(args)
    if args.command == "atlas":
        return _run_atlas(args)
    if args.command == "trust":
        return _run_trust(args)
    if args.command == "baseline":
        return _run_baseline(args)
    if args.command == "diff":
        return _run_diff(args)
    return _run_scan(args)


_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def _run_trust(args: argparse.Namespace) -> int:
    """The agent-trust command (Tier 4). Scores what each tool is trusted with."""
    from .report import RenderOptions
    from .report.writer import write_report
    from .trust import collect_trust
    from .trust.render import render_json_trust, render_terminal_trust

    report = collect_trust(roots=args.root)
    opts = RenderOptions(absolute_paths=args.absolute_paths, home=str(Path.home()))

    print(render_terminal_trust(report, opts), end="")
    if args.json is not None:
        write_report(args.json, render_json_trust(report, opts))
        print(f"wrote trust JSON: {args.json}", file=sys.stderr)

    if args.min_grade is not None:
        floor = _GRADE_RANK[args.min_grade]
        if any(_GRADE_RANK[p.grade] > floor for p in report.profiles):
            return 1
    return 0


def _posture_snapshot(args: argparse.Namespace) -> Snapshot:
    """Run a scan (+ inventory unless --no-inventory) and build a drift Snapshot."""
    from .drift import build_snapshot
    from .engine import scan

    report = scan(roots=args.root, online=args.online)
    inventory = None
    if not args.no_inventory:
        from .inventory import collect_inventory

        inventory = collect_inventory(roots=args.root, probe=not args.no_probe)
    return build_snapshot(report, inventory)


def _run_baseline(args: argparse.Namespace) -> int:
    """Write a signed-by-digest posture snapshot (Tier 5)."""
    from datetime import datetime

    from .drift import render_baseline
    from .report.writer import write_report

    snapshot = _posture_snapshot(args)
    created_at = datetime.now(UTC).isoformat()
    text = render_baseline(snapshot, created_at=created_at)

    if args.out is not None:
        write_report(args.out, text)
        print(f"wrote baseline: {args.out} ({len(snapshot.facts)} facts)", file=sys.stderr)
    else:
        print(text, end="")
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    """Compare the current posture against a baseline snapshot (Tier 5)."""
    from datetime import datetime

    from .drift import (
        BaselineError,
        assess_staleness,
        baseline_created_at,
        diff_snapshots,
        load_baseline,
    )
    from .drift.render import render_json_drift, render_terminal_drift
    from .report.writer import write_report

    if args.baseline is None:
        print("error: 'diff' requires --baseline PATH", file=sys.stderr)
        return 2
    try:
        baseline_text = args.baseline.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read baseline {args.baseline}: {exc}", file=sys.stderr)
        return 2
    try:
        baseline = load_baseline(baseline_text)
    except BaselineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # "today" is computed here, once — the staleness helper stays deterministic.
    staleness = assess_staleness(
        baseline_created_at(baseline_text),
        today=datetime.now(UTC).date(),
        max_age_days=args.max_age_days,
    )

    current = _posture_snapshot(args)
    report = diff_snapshots(baseline, current)

    print(render_terminal_drift(report, staleness=staleness), end="")
    if args.json is not None:
        write_report(args.json, render_json_drift(report, staleness=staleness))
        print(f"wrote drift JSON: {args.json}", file=sys.stderr)

    if args.fail_on_regression and report.regressions:
        return 1
    # Stale age gates only under the explicit opt-in flag (gate polarity: a
    # decayed-but-unchanged posture must not fail CI unless asked to).
    if args.fail_on_stale and staleness.stale:
        return 1
    return 0


def _run_atlas(args: argparse.Namespace) -> int:
    """The framework-mapping command (Tier 2). A citation view over scan."""
    # Imported lazily so the default/help path stays light and import-isolated.
    from .atlas.render import render_json_atlas, render_terminal_atlas, render_terminal_matrix
    from .engine import scan
    from .report import RenderOptions
    from .report.writer import write_report

    if args.matrix:
        print(render_terminal_matrix(), end="")
        return 0

    report = scan(roots=args.root, online=args.online)
    opts = RenderOptions(absolute_paths=args.absolute_paths, home=str(Path.home()))

    print(render_terminal_atlas(report, opts), end="")
    if args.json is not None:
        write_report(args.json, render_json_atlas(report, opts))
        print(f"wrote JSON atlas: {args.json}", file=sys.stderr)

    # Same gate semantics as scan: the atlas is a view over the same findings.
    return _exit_code(report, args.fail_on)


def _run_inventory(args: argparse.Namespace) -> int:
    """The AI/MCP asset-inventory command (Tier 1). Observes; never judges."""
    # Imported lazily so the default/help path stays light and import-isolated.
    from .inventory import collect_inventory
    from .inventory.render import render_json_inventory, render_terminal_inventory
    from .report import RenderOptions
    from .report.writer import write_report

    inventory = collect_inventory(roots=args.root, probe=not args.no_probe)
    opts = RenderOptions(absolute_paths=args.absolute_paths, home=str(Path.home()))

    print(render_terminal_inventory(inventory, opts), end="")
    if args.json is not None:
        write_report(args.json, render_json_inventory(inventory, opts))
        print(f"wrote JSON inventory: {args.json}", file=sys.stderr)

    # Inventory is an observation, not a gate: it always exits 0.
    return 0


def _run_scan(args: argparse.Namespace) -> int:
    """The localhost scan command (default)."""
    # Imported lazily so the default/help path stays light and import-isolated.
    from .engine import scan
    from .report import RenderOptions
    from .report.html import render_html
    from .report.json_report import render_json
    from .report.sarif import render_sarif
    from .report.terminal import render_terminal
    from .report.writer import write_report

    if args.show_secrets:
        print(
            "warning: --show-secrets reveals masked secret values; keep the output private.",
            file=sys.stderr,
        )
    if args.online:
        print(
            "note: --online contacts api.osv.dev with package name+version only "
            "(no config contents, paths, or secrets).",
            file=sys.stderr,
        )

    report = scan(roots=args.root, online=args.online)
    report = _apply_acceptance_ledger(report, args.root)
    opts = RenderOptions(
        show_secrets=args.show_secrets,
        absolute_paths=args.absolute_paths,
        home=str(Path.home()),
    )

    # Redaction-safe by construction: secrets are reduced to non-reversible
    # fingerprints at detection (redaction.fingerprint_secret) and never reach
    # the report raw. Default output shows only "[redacted len=N sha256:XX]";
    # --show-secrets reveals at most a first-2/last-2 masked preview and prints a
    # warning (see report.common.secret_str, docs/SECURITY_SIGNOFF.md, T-305).
    # CodeQL py/clear-text-logging-sensitive-data flags this sink because it
    # can't model that redaction boundary as a sanitizer — accepted, documented.
    print(render_terminal(report, opts), end="")
    if args.json is not None:
        write_report(args.json, render_json(report, opts))
        print(f"wrote JSON report: {args.json}", file=sys.stderr)
    if args.html is not None:
        write_report(args.html, render_html(report, opts))
        print(f"wrote HTML report: {args.html}", file=sys.stderr)
    if args.sarif is not None:
        # Relativize repo-local paths to cwd so GitHub code scanning can map them.
        write_report(args.sarif, render_sarif(report, opts, base=str(Path.cwd())))
        print(f"wrote SARIF report: {args.sarif}", file=sys.stderr)

    if args.fix:
        _apply_fixes(args.root, opts)

    return _exit_code(report, args.fail_on)


def _run_lan(args: argparse.Namespace) -> int:
    """The authorized network-assessment command ('lan')."""
    from datetime import datetime

    from . import __version__
    from .lan import LanRefusal, run_lan
    from .lan.audit import audit_record_to_dict
    from .lan.policy import PolicyError, load_policy
    from .report import RenderOptions
    from .report.json_report import report_to_dict
    from .report.terminal import render_terminal
    from .report.writer import write_report

    if args.manifest is None or args.invoker is None:
        print("error: 'lan' requires --manifest and --invoker {human,agent}", file=sys.stderr)
        return 2
    try:
        manifest_bytes = args.manifest.read_bytes()
    except OSError as exc:
        print(f"error: cannot read manifest {args.manifest}: {exc}", file=sys.stderr)
        return 2

    public_allowlist: tuple[str, ...] | None = None
    if args.enterprise_policy is not None:
        try:
            policy_bytes = args.enterprise_policy.read_bytes()
        except OSError as exc:
            print(
                f"error: cannot read enterprise policy {args.enterprise_policy}: {exc}",
                file=sys.stderr,
            )
            return 2
        policy = load_policy(policy_bytes)
        if isinstance(policy, PolicyError):
            print(f"error: invalid enterprise policy: {policy.message}", file=sys.stderr)
            return 2
        public_allowlist = policy.public_targets

    signature = args.signature or Path(str(args.manifest) + ".sig")
    print(
        "note: 'lan' probes the authorized targets in the manifest (TCP connect + a "
        "bare MCP handshake). It is exposure-only and never reads a remote config.",
        file=sys.stderr,
    )

    outcome = run_lan(
        manifest_bytes=manifest_bytes,
        now=datetime.now(UTC),
        invoker=args.invoker,
        tool_version=__version__,
        argv=sys.argv,
        signature_path=signature,
        allowed_signers=args.allowed_signers,
        public_allowlist=public_allowlist,
        dry_run=args.dry_run,
    )
    if isinstance(outcome, LanRefusal):
        print(f"refused: {outcome.reason}", file=sys.stderr)
        return 2

    audit = outcome.audit
    print(
        f"authorized run {audit.authorization_id} (operator {audit.operator}); "
        f"manifest sha256:{audit.manifest_sha256[:12]}",
        file=sys.stderr,
    )
    opts = RenderOptions(absolute_paths=args.absolute_paths, home=str(Path.home()))
    if outcome.dry_run:
        plan = f"{len(outcome.plan_hosts)} host(s) × {len(outcome.plan_ports)} port(s)"
        print(f"[dry-run] verified plan: {plan}; no packets sent.", file=sys.stderr)
        for host in outcome.plan_hosts:
            print(f"  would probe {host} on ports {list(outcome.plan_ports)}", file=sys.stderr)
    else:
        print(render_terminal(outcome.report, opts), end="")

    if args.json is not None:
        payload = {
            "audit": audit_record_to_dict(audit),
            "report": report_to_dict(outcome.report, opts),
        }
        write_report(args.json, json.dumps(payload, indent=2, sort_keys=True) + "\n")
        print(f"wrote LAN JSON report: {args.json}", file=sys.stderr)

    if args.sarif is not None:
        # LAN findings are network endpoints, emitted as SARIF logical locations
        # (ADR-16) — standards-valid for generic SARIF/SIEM consumers. GitHub code
        # scanning needs a physical file and will not raise alerts from these.
        from .report.sarif import render_sarif

        write_report(args.sarif, render_sarif(outcome.report, opts, logical_locations=True))
        print(
            f"wrote LAN SARIF report: {args.sarif} "
            "(logical locations; for generic SARIF/SIEM consumers, not GitHub code scanning)",
            file=sys.stderr,
        )

    return _exit_code(outcome.report, args.fail_on)


def _apply_fixes(roots: list[Path] | None, opts: object) -> None:
    """Apply safe tool-scope remediations to discovered configs (``--fix``).

    The single, explicit exception to advise-only: writes only when asked, backs
    each file up first, and touches only over-broad permission/autoApprove grants.
    """
    from .engine import discover_host_config_files
    from .fix import apply_fix_to_file, plan_config_fixes
    from .io_safe import SafeReadError, safe_read_text

    print(
        "note: --fix modifies config files in place (backup written to "
        "<path>.mcpscan.bak). Only over-broad tool-scope grants are removed; "
        "credential and pinning findings still need a manual fix.",
        file=sys.stderr,
    )

    total = 0
    for path in discover_host_config_files(roots=roots):
        try:
            raw = safe_read_text(path, root=path.parent)
        except SafeReadError:
            continue
        plan = plan_config_fixes(str(path), raw)
        if not plan.changed or plan.new_text is None:
            continue
        backup = apply_fix_to_file(path, plan.new_text)
        total += len(plan.fixes)
        print(f"fixed {path} ({len(plan.fixes)} change(s); backup: {backup})", file=sys.stderr)
        for fx in plan.fixes:
            print(f"    removed {fx.removed!r} from {fx.where} [{fx.rule_id}]", file=sys.stderr)

    if total == 0:
        print("no auto-fixable tool-scope findings.", file=sys.stderr)
    else:
        print(f"applied {total} fix(es). Re-run mcpscan to confirm.", file=sys.stderr)


def _apply_acceptance_ledger(report: Report, roots: list[Path] | None) -> Report:
    """Attach per-root ``.mcpscan-accept.json`` acceptances to the report.

    Ledger warnings (malformed files, entries naming non-tool-scope findings)
    go to stderr. "today" for expiry is computed here, once, so the acceptance
    module stays deterministic (no clock reads outside the CLI layer).
    """
    from datetime import datetime

    from .acceptance import apply_acceptances, load_ledgers

    ledger = load_ledgers(roots if roots is not None else [Path.cwd()])
    for warning in ledger.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not ledger.entries:
        return report
    report, apply_warnings = apply_acceptances(
        report, ledger.entries, today=datetime.now(UTC).date()
    )
    for warning in apply_warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return report


def _exit_code(report: Report, fail_on: str) -> int:
    """Non-zero if any finding is at/above the configured threshold.

    A finding carrying an UNEXPIRED acceptance is skipped by the gate — and
    only by the gate: grades still count accepted findings (posture is what it
    is; acceptance relaxes CI failure, not the measurement). An expired
    acceptance no longer shields the finding, so it gates again.
    """
    blocking = _THRESHOLDS[fail_on]
    has_blocking = any(
        f.severity in blocking
        for s in report.servers
        for f in s.findings
        if f.acceptance is None or f.acceptance.expired
    )
    return 1 if has_blocking else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
