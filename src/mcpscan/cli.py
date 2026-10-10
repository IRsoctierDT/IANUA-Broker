# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for IANUA-Broker (``mcpscan``).

Wires the scan engine to the renderers. Honors the spec's trust properties:
offline by default, secrets redacted unless ``--show-secrets``, and — advise-only
by default — the only file writes are the reports the user explicitly requests
(``--json`` / ``--html`` / ``--sarif``) plus the config edits of opt-in ``--fix``.

Commands: ``scan`` (localhost posture, the default surface), ``inventory``
(classified AI/MCP asset list — observes, never judges; see ``mcpscan.inventory``),
``atlas`` (the same findings mapped to security frameworks; see ``mcpscan.atlas``),
``trust`` (a per-agent Trust Score and the risky factor combinations; see
``mcpscan.trust``), ``graph`` (an AI attack-path graph over cross-server
credential/tool chaining; see ``mcpscan.graph``), ``baseline`` / ``diff`` (a
posture snapshot and drift against
it; see ``mcpscan.drift``), ``lan`` (authorized network assessment — inert
without a signed manifest; see ``mcpscan.lan``), ``schedule`` (emit an
OS-native scheduler unit that re-runs scan+diff on a cadence — no daemon; see
``mcpscan.schedule``), ``selftest`` (run the scanner against a known-bad
throwaway fixture to confirm its core detections still fire; see
``mcpscan.selftest``), and ``update-datapack`` (verify a signed detection
data-pack and install it into the local store; see ``mcpscan.datapack``).
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
    from .drift import DriftReport, Snapshot
    from .graph import AttackGraph

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
        choices=[
            "scan",
            "inventory",
            "atlas",
            "trust",
            "graph",
            "baseline",
            "diff",
            "lan",
            "schedule",
            "selftest",
            "update-datapack",
        ],
        help=(
            "The action to run: 'scan' (localhost posture), 'inventory' (classified "
            "AI/MCP asset list), 'atlas' (findings mapped to security frameworks), "
            "'trust' (per-agent Trust Score + risk relationships), 'graph' (AI "
            "attack-path graph: cross-server credential/tool-chaining), 'baseline' "
            "(write a posture snapshot), 'diff' (drift vs a baseline), 'lan' "
            "(authorized network assessment), 'schedule' (emit an OS scheduler unit "
            "that runs scan+diff on a cadence), 'selftest' (confirm the scanner's "
            "core detections still fire against a known-bad fixture), or "
            "'update-datapack' (verify a signed detection data-pack and install it "
            "locally)."
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
        help=(
            "Write a SARIF 2.1.0 report for GitHub code scanning. With 'diff': one "
            "alert per regression vs the baseline, with before/after detail."
        ),
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
    parser.add_argument(
        "--inspect-token-stores",
        action="store_true",
        help=(
            "Read the on-disk credential/token stores of discovered hosts (e.g. "
            "Claude Code's ~/.claude/.credentials.json) to grade file permissions "
            "and, via an offline JWT decode, flag tokens already expired. No token "
            "value is stored or printed. Off by default (reads nothing extra)."
        ),
    )
    parser.add_argument(
        "--inspect-process-env",
        action="store_true",
        help=(
            "Read the environment blocks of your own running agent/MCP processes "
            "to detect plaintext secrets. Values are redacted to a fingerprint at "
            "detection, never stored or printed. Only your own processes are "
            "readable. Off by default (enumerates no processes)."
        ),
    )
    parser.add_argument(
        "--inspect-telemetry",
        action="store_true",
        help=(
            "Read the metadata (existence, permissions, last-modified time) of "
            "discovered hosts' agent/MCP log surfaces to grade logging health: "
            "absent/empty logging, group/world-readable logs, or long-stale logs. "
            "Only log metadata is read, never log contents. Off by default "
            "(reads nothing extra)."
        ),
    )
    parser.add_argument(
        "--inspect-broker",
        action="store_true",
        help=(
            "Read the documented Agent Trust Broker manifest (broker.json) and "
            "grade whether privileged servers are fronted by a sound broker "
            "(present, least-privilege allowlist, signed tool manifests, audit "
            "log on). Assessment-only: reads the manifest, never writes or "
            "contacts the broker. The manifest holds no secrets. Off by default "
            "(reads nothing extra)."
        ),
    )
    parser.add_argument(
        "--inspect-live-tools",
        action="store_true",
        help=(
            "Opt-in: speak MCP (initialize + tools/list) to loopback endpoints only "
            "and check the tool names, descriptions, schemas and annotations the "
            "server actually advertises. Targets: every --live-tools-target, plus "
            "listening sockets owned by a positively identified agent/MCP process. "
            "No credentials, no proxy, no redirects, no LAN/WAN. With baseline/diff "
            "the manifest digest is fingerprinted, so a changed tool is drift."
        ),
    )
    parser.add_argument(
        "--import-mcp-lock",
        metavar="PATH",
        type=Path,
        help=(
            "With 'baseline': also pin every approved tool from an mcpseal "
            ".mcp-lock.json (server NAME becomes stdio://NAME, matching "
            "--spawn-stdio NAME=...). Only digests are imported, never the "
            "plaintext descriptions the lockfile stores. Unknown lockfile "
            "versions are refused."
        ),
    )
    parser.add_argument(
        "--spawn-stdio",
        action="append",
        default=[],
        type=_stdio_target,
        metavar="NAME=IMAGE@sha256:DIGEST",
        help=(
            "Inspect a stdio-only MCP server with --inspect-live-tools by running "
            "its operator-supplied container image (pinned by digest; never pulled) "
            "in the ADR-18 sandbox: no network, read-only root, no host env or "
            "mounts, CPU/memory/process limits. RUNS THE SERVER'S CODE inside the "
            "container. Repeatable. Fails closed without podman/docker."
        ),
    )
    parser.add_argument(
        "--tools-json",
        action="append",
        default=[],
        type=_tools_json_target,
        metavar="[NAME=]PATH",
        help=(
            "Check a saved MCP tools/list document offline (repeatable): a tools/list "
            "result, a full JSON-RPC response, or a bare tools array. Same checks and "
            "bounds as --inspect-live-tools, with no connection; findings point at "
            "the file. Reported as server tools-json://NAME (default NAME: the file "
            "stem). With baseline/diff each tool is pinned, so a changed file is drift."
        ),
    )
    parser.add_argument(
        "--container-runtime",
        choices=("auto", "podman", "docker"),
        default="auto",
        help="Container runtime for --spawn-stdio (default: auto = podman, then docker).",
    )
    parser.add_argument(
        "--live-tools-target",
        action="append",
        default=[],
        type=_live_target,
        metavar="HOST:PORT[/PATH]",
        help=(
            "Loopback MCP endpoint for --inspect-live-tools (repeatable), e.g. "
            "127.0.0.1:8765/mcp. Path defaults to /mcp. Non-loopback hosts are "
            "rejected."
        ),
    )

    emit = parser.add_argument_group(
        "emit", "Alert emission (used with 'scan' / 'diff'): push a REDACTED summary to a sink."
    )
    emit.add_argument(
        "--emit",
        action="append",
        choices=("ndjson", "webhook", "syslog"),
        metavar="SINK",
        help=(
            "Emit a redacted findings/drift summary to a sink (repeatable): "
            "'ndjson' (append a JSON line to --emit-ndjson-path), 'webhook' (POST "
            "JSON to --emit-webhook-url), or 'syslog' (local syslog). Off by "
            "default; no secret value is ever sent — only an 8-hex fingerprint."
        ),
    )
    emit.add_argument(
        "--emit-ndjson-path",
        metavar="PATH",
        type=Path,
        help="emit: file the 'ndjson' sink appends one JSON alert line to.",
    )
    emit.add_argument(
        "--emit-webhook-url",
        metavar="URL",
        help=(
            "emit: HTTP(S) endpoint the 'webhook' sink POSTs the alert to "
            "(egress; the destination host is disclosed to stderr before the POST)."
        ),
    )
    emit.add_argument(
        "--emit-syslog",
        action="store_true",
        help="emit: send the alert to the local syslog (equivalent to --emit syslog).",
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
        "--require-baseline-signature",
        action="store_true",
        help=(
            "diff: refuse unsigned baselines (require --signature and "
            "--allowed-signers). Recommended for CI drift gates."
        ),
    )
    drift.add_argument(
        "--no-inventory",
        action="store_true",
        help=(
            "baseline/diff/graph: work from posture/trust data alone, skipping the "
            "AI/MCP asset inventory."
        ),
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

    graph = parser.add_argument_group(
        "graph", "AI attack-path graph (used only with the 'graph' command)."
    )
    graph.add_argument(
        "--graph-format",
        choices=("text", "dot"),
        default="text",
        help=(
            "graph: stdout format — 'text' (human attack-chain report, the default) "
            "or 'dot' (Graphviz DOT export to draw the graph). --json still writes "
            "the machine-readable graph JSON in either mode."
        ),
    )

    schedule = parser.add_argument_group(
        "schedule", "OS scheduler unit generation (used only with the 'schedule' command)."
    )
    schedule.add_argument(
        "--cadence",
        choices=("hourly", "daily", "weekly"),
        help=(
            "schedule: how often the generated unit runs 'mcpscan scan' + "
            "'mcpscan diff'. Required for the 'schedule' command."
        ),
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
        help=(
            "Detached signature over the signed input: the manifest ('lan'), the "
            "data-pack ('update-datapack'), or the baseline ('diff')."
        ),
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

    datapack = parser.add_argument_group(
        "update-datapack",
        "Signed detection data-pack refresh (used only with 'update-datapack'). "
        "Reuses --signature and --allowed-signers from the 'lan' group.",
    )
    datapack.add_argument(
        "--pack",
        metavar="PATH",
        type=Path,
        help="update-datapack: the detection data-pack JSON file to verify and install.",
    )
    datapack.add_argument(
        "--signer",
        metavar="ID",
        help=(
            "The signer identity to check against --allowed-signers, for "
            "'update-datapack' and for a signed baseline on 'diff' (default: the "
            "first principal named in that file)."
        ),
    )
    datapack.add_argument(
        "--scheme",
        choices=("ssh", "ed25519"),
        default="ssh",
        help=(
            "The signature scheme for 'update-datapack' and for verifying a signed "
            "baseline on 'diff' (default: ssh, dependency-free)."
        ),
    )
    return parser


def _stdio_target(text: str) -> tuple[str, str]:
    """Parse ``NAME=IMAGE`` for --spawn-stdio; the image must be pinned by digest."""
    from .discovery.stdio_sandbox import pinned_image, valid_server_name

    name, sep, image = text.partition("=")
    if not sep or not valid_server_name(name):
        raise argparse.ArgumentTypeError(
            "expected NAME=IMAGE@sha256:DIGEST (NAME: 1-64 of A-Z a-z 0-9 . _ -)"
        )
    if not pinned_image(image):
        raise argparse.ArgumentTypeError(
            "image must be pinned by digest (repo@sha256:<64 hex> or sha256:<64 hex>); "
            "tags are refused because they can change"
        )
    return name, image


def _tools_json_target(text: str) -> tuple[str, Path]:
    """Parse ``[NAME=]PATH`` for --tools-json; the file must exist and be regular.

    Without ``NAME=`` the server name is the file stem, which must itself be a
    valid name (1-64 of ``A-Z a-z 0-9 . _ -``, alphanumeric first).
    """
    from .discovery.stdio_sandbox import valid_server_name

    name, sep, rest = text.partition("=")
    if sep and valid_server_name(name):
        path = Path(rest)
    else:
        path = Path(text)
        name = path.stem
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"{path}: not an existing regular file")
    if not valid_server_name(name):
        raise argparse.ArgumentTypeError(
            f"cannot use {name!r} as a server name; pass NAME=PATH "
            "(NAME: 1-64 of A-Z a-z 0-9 . _ -)"
        )
    return name, path


def _live_target(text: str) -> tuple[str, int, str]:
    """Parse ``HOST:PORT[/PATH]`` (IPv6 as ``[::1]:PORT``); loopback hosts only."""
    from .discovery.sockets import is_loopback

    rest, slash, path = text.partition("/")
    path = slash + path if slash else "/mcp"
    if rest.startswith("["):
        host, _, port_text = rest[1:].partition("]:")
    else:
        host, _, port_text = rest.rpartition(":")
    if not host or not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise argparse.ArgumentTypeError("expected HOST:PORT[/PATH], e.g. 127.0.0.1:8765/mcp")
    if not is_loopback(host):
        raise argparse.ArgumentTypeError("only loopback hosts may be inspected (ADR-1)")
    if len(path) > 256 or any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in path):
        raise argparse.ArgumentTypeError("path must be printable ASCII without spaces")
    return host, int(port_text), path


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if (args.live_tools_target or args.spawn_stdio) and not args.inspect_live_tools:
        # Fail closed: a target alone must never look like an inspection happened.
        parser.error("--live-tools-target/--spawn-stdio require --inspect-live-tools")

    if args.tools_json and args.command not in {"scan", "baseline", "diff"}:
        # Fail closed: an accepted-but-ignored manifest would look inspected.
        parser.error("--tools-json is used only with scan, baseline and diff")
    names = [name for name, _path in args.tools_json]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        parser.error(f"--tools-json server names must be unique: {', '.join(duplicates)}")

    if args.command == "lan":
        return _run_lan(args)
    if args.command == "inventory":
        return _run_inventory(args)
    if args.command == "atlas":
        return _run_atlas(args)
    if args.command == "trust":
        return _run_trust(args)
    if args.command == "graph":
        return _run_graph(args)
    if args.command == "baseline":
        return _run_baseline(args)
    if args.command == "diff":
        return _run_diff(args)
    if args.command == "schedule":
        return _run_schedule(args)
    if args.command == "selftest":
        return _run_selftest(args)
    if args.command == "update-datapack":
        return _run_update_datapack(args)
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


def _run_graph(args: argparse.Namespace) -> int:
    """The AI attack-path graph command (Tier 3). Reasons about chaining.

    Builds a pure graph over data the scanner already collects (trust profiles,
    the AI/MCP inventory, shared-credential fingerprints) plus one safe inference
    (a credential key name -> the target it unlocks), then enumerates the
    actionable attacker chains — exposed surface -> shared credential / privileged
    tool -> high-value target. Offline and secretless. Default renders the human
    chain report; ``--graph-format dot`` emits a Graphviz export; ``--json``
    writes the machine-readable graph. ``--fail-on`` gates CI on the worst chain.
    """
    from .graph import collect_graph, render_dot_graph, render_json_graph, render_terminal_graph
    from .report import RenderOptions
    from .report.writer import write_report

    graph = collect_graph(roots=args.root, inventory=not args.no_inventory)
    opts = RenderOptions(absolute_paths=args.absolute_paths, home=str(Path.home()))

    if args.graph_format == "dot":
        print(render_dot_graph(graph), end="")
    else:
        print(render_terminal_graph(graph, opts), end="")

    if args.json is not None:
        write_report(args.json, render_json_graph(graph, opts))
        print(f"wrote graph JSON: {args.json}", file=sys.stderr)

    return _graph_exit_code(graph, args.fail_on)


def _graph_exit_code(graph: AttackGraph, fail_on: str) -> int:
    """Non-zero if any enumerated attack chain is at/above the threshold.

    The path-severity twin of :func:`_exit_code`: the graph's unit of risk is a
    whole chain, not a per-finding deduction, so it gates on ``path.severity``
    against the same ``_THRESHOLDS`` map ``scan`` uses.
    """
    blocking = _THRESHOLDS[fail_on]
    return 1 if any(path.severity in blocking for path in graph.paths) else 0


def _disclose_live_tools(args: argparse.Namespace) -> None:
    """Print the live-tools disclosure banner (stderr), naming explicit targets."""
    explicit = ", ".join(f"{h}:{p}{path}" for h, p, path in args.live_tools_target) or "none"
    print(
        "note: --inspect-live-tools sends MCP initialize + tools/list to loopback "
        f"endpoints only (explicit: {explicit}; plus sockets owned by identified "
        "agent/MCP processes). No credentials are sent; no proxy or redirect is "
        "followed; nothing leaves this host.",
        file=sys.stderr,
    )
    for name, image in args.spawn_stdio:
        print(
            f"note: --spawn-stdio runs server {name!r} from image {image} inside a "
            f"{args.container_runtime} container: --network none, read-only root, "
            "no host environment or mounts, resource-limited, removed on exit. "
            "The server's code executes inside that container.",
            file=sys.stderr,
        )
    if not args.live_tools_target and not args.spawn_stdio:
        print(
            "note: no --live-tools-target given; only auto-identified agent sockets "
            "will be inspected.",
            file=sys.stderr,
        )


def _posture_snapshot(args: argparse.Namespace) -> Snapshot:
    """Run a scan (+ inventory unless --no-inventory) and build a drift Snapshot."""
    from .drift import build_snapshot
    from .engine import scan

    if args.inspect_live_tools:
        _disclose_live_tools(args)
    report = scan(
        roots=args.root,
        online=args.online,
        inspect_live_tools=args.inspect_live_tools,
        live_tools_targets=tuple(args.live_tools_target),
        stdio_targets=tuple(args.spawn_stdio),
        container_runtime=args.container_runtime,
        tools_json_targets=tuple(args.tools_json),
    )
    inventory = None
    if not args.no_inventory:
        from .inventory import collect_inventory

        inventory = collect_inventory(roots=args.root, probe=not args.no_probe)
    return build_snapshot(report, inventory)


def _run_baseline(args: argparse.Namespace) -> int:
    """Write a posture snapshot carrying an integrity digest (Tier 5).

    The digest is a hash, not a signature: it catches corruption, not a
    motivated editor. Where the baseline is a control — CI, where "no drift" is
    the thing being trusted — sign it and verify on ``diff``; the guidance below
    prints the exact command. Signing is the operator's action with their own
    key, so this tool never handles private key material.
    """
    from datetime import datetime

    from .drift import render_baseline
    from .drift.baseline import BASELINE_SSH_NAMESPACE
    from .report.writer import write_report

    snapshot = _posture_snapshot(args)
    if args.import_mcp_lock is not None:
        imported = _import_mcp_lock(args.import_mcp_lock, snapshot)
        if imported is None:
            return 2
        snapshot = imported
    created_at = datetime.now(UTC).isoformat()
    text = render_baseline(snapshot, created_at=created_at)

    if args.out is not None:
        write_report(args.out, text)
        print(f"wrote baseline: {args.out} ({len(snapshot.facts)} facts)", file=sys.stderr)
        print(
            "note: the baseline carries an integrity digest, which detects corruption "
            "but not deliberate editing — anyone who can rewrite the file can "
            "recompute it. To make drift trustworthy where the file is shared, sign "
            "it and verify on diff:\n"
            f"  ssh-keygen -Y sign -f <key> -n {BASELINE_SSH_NAMESPACE} {args.out}\n"
            f"  mcpscan diff --baseline {args.out} --signature {args.out}.sig "
            "--allowed-signers <file>",
            file=sys.stderr,
        )
    else:
        print(text, end="")
    return 0


def _import_mcp_lock(path: Path, snapshot: Snapshot) -> Snapshot | None:
    """Merge mcpseal pins into a baseline snapshot; None (exit 2) if the file is refused.

    A key the live scan already pinned wins: the scan observed more than the
    lockfile can vouch for. Every refusal and skip is reported on stderr.
    """
    from .drift import Snapshot
    from .drift.mcpseal_import import MAX_LOCKFILE_BYTES, LockfileImportError, parse_mcp_lock

    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"error: cannot read {path}: {exc.strerror}", file=sys.stderr)
        return None
    if len(raw) > MAX_LOCKFILE_BYTES:
        print(f"error: {path} is larger than 4 MiB; refusing it", file=sys.stderr)
        return None
    try:
        loaded = parse_mcp_lock(raw.decode("utf-8"))
    except (UnicodeDecodeError, LockfileImportError) as exc:
        print(f"error: refusing {path}: {exc}", file=sys.stderr)
        return None
    for warning in loaded.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    present = {f.key for f in snapshot.facts}
    added = [f for f in loaded.facts if f.key not in present]
    tools = sum(1 for f in added if f.kind.value == "tool")
    print(
        f"note: imported {tools} mcpseal tool pin(s) from {path} "
        "(digests only; provenance mcpseal-import).",
        file=sys.stderr,
    )
    facts = sorted((*snapshot.facts, *added), key=lambda f: (f.kind.value, f.key))
    return Snapshot(schema_version=snapshot.schema_version, facts=tuple(facts))


def _run_diff(args: argparse.Namespace) -> int:
    """Compare the current posture against a baseline snapshot (Tier 5)."""
    from datetime import datetime

    from .datapack import first_allowed_signer
    from .drift import (
        BaselineError,
        assess_staleness,
        baseline_created_at,
        diff_snapshots,
        load_baseline,
    )
    from .drift.baseline import load_verified_baseline
    from .drift.render import render_json_drift, render_terminal_drift
    from .report.writer import write_report

    if args.baseline is None:
        print("error: 'diff' requires --baseline PATH", file=sys.stderr)
        return 2
    try:
        baseline_bytes = args.baseline.read_bytes()
    except OSError as exc:
        print(f"error: cannot read baseline {args.baseline}: {exc}", file=sys.stderr)
        return 2
    try:
        baseline_text = baseline_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        print(f"error: baseline {args.baseline} is not valid UTF-8: {exc}", file=sys.stderr)
        return 2

    # Opt-in signature verification. Half a configuration is a trap — an operator
    # who passes only one of the two flags believes the baseline is verified when
    # it is not — so the pair is required together rather than silently ignored.
    require_sig = bool(getattr(args, "require_baseline_signature", False))
    if require_sig and args.signature is None and args.allowed_signers is None:
        print(
            "error: --require-baseline-signature needs --signature and --allowed-signers",
            file=sys.stderr,
        )
        return 2
    if args.signature is not None or args.allowed_signers is not None:
        if args.signature is None or args.allowed_signers is None:
            print(
                "error: verifying a baseline needs both --signature and --allowed-signers",
                file=sys.stderr,
            )
            return 2
        try:
            signers_text = args.allowed_signers.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"error: cannot read {args.allowed_signers}: {exc}", file=sys.stderr)
            return 2
        operator = args.signer or first_allowed_signer(signers_text)
        if operator is None:
            print(
                "error: cannot determine the signer identity from --allowed-signers; "
                "pass --signer ID",
                file=sys.stderr,
            )
            return 2
        print(
            f"note: verifying {args.baseline} against {args.allowed_signers} "
            f"(scheme {args.scheme}, signer {operator!r}) before trusting it.",
            file=sys.stderr,
        )
        try:
            baseline = load_verified_baseline(
                baseline_bytes,
                args.signature,
                args.allowed_signers,
                operator=operator,
                scheme=args.scheme,
            )
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
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
    report = _apply_tool_drift_ledger(report, args.root)

    print(render_terminal_drift(report, staleness=staleness), end="")
    if args.json is not None:
        write_report(args.json, render_json_drift(report, staleness=staleness))
        print(f"wrote drift JSON: {args.json}", file=sys.stderr)
    if args.sarif is not None:
        from .drift.sarif import render_sarif_drift
        from .report import RenderOptions

        sarif = render_sarif_drift(
            report,
            baseline_path=str(args.baseline.resolve()),
            opts=RenderOptions(absolute_paths=args.absolute_paths, home=str(Path.home())),
            base=str(Path.cwd()),
        )
        write_report(args.sarif, sarif)
        print(f"wrote drift SARIF: {args.sarif}", file=sys.stderr)

    code = 0
    if args.fail_on_regression and report.regressions:
        code = 1
    # Stale age gates only under the explicit opt-in flag (gate polarity: a
    # decayed-but-unchanged posture must not fail CI unless asked to).
    if args.fail_on_stale and staleness.stale:
        code = 1

    threshold = "regression" if args.fail_on_regression else "none"
    _emit_alerts(args, report, kind="diff", gate_failed=bool(code), threshold=threshold)
    return code


_DEFAULT_BASELINE_NAME = ".mcpscan-baseline.json"


def _resolve_mcpscan_invocation() -> tuple[tuple[str, ...], str | None]:
    """Resolve how a scheduler invokes mcpscan: ``(argv, pythonpath)``.

    Kept in the CLI (never the pure generators) so :mod:`mcpscan.schedule` stays
    I/O-free. Prefers an installed ``mcpscan`` on PATH; otherwise falls back to
    ``python -m mcpscan`` so a venv/editable install still schedules cleanly.
    The scheduler runs that fallback in a bare environment (no ``PYTHONPATH``,
    different cwd), so for a source-tree run — this package importable only via
    such a transient search-path entry — the second element is the package
    parent for the generators to bake into the command as ``PYTHONPATH``;
    without it every scheduled run would die with ``ModuleNotFoundError``.
    """
    import shutil

    exe = shutil.which("mcpscan")
    if exe is not None:
        return (exe,), None
    return (sys.executable, "-m", "mcpscan"), _transient_package_parent()


def _transient_package_parent() -> str | None:
    """The search-path entry mcpscan imports through, iff it is transient.

    "Transient" search-path entries are the ones a scheduler's bare environment
    does not reproduce: the interpreter start directory (``sys.path[0]``) and
    ``PYTHONPATH``. If this package is reachable through one of those (a
    ``PYTHONPATH=src`` source-tree run), return that entry for the unit to bake
    as ``PYTHONPATH``; for an installed package (site-packages), which a bare
    interpreter finds on its own, return None. Matching resolves
    ``<entry>/mcpscan`` against the real package directory instead of comparing
    the entry to the package parent, so a package dir *symlinked* from under
    the entry (an aggregation ``src/`` of links) still matches — the
    parent-comparison form resolves the two sides asymmetrically and would
    silently emit a unit that dies with ``ModuleNotFoundError``.
    """
    import os

    package_dir = Path(__file__).resolve().parent
    entries: list[str] = []
    if sys.path and sys.path[0]:
        entries.append(sys.path[0])
    entries.extend(e for e in os.environ.get("PYTHONPATH", "").split(os.pathsep) if e)
    for entry in entries:
        candidate = Path(os.path.abspath(entry))
        try:
            if (candidate / "mcpscan").resolve() == package_dir:
                return str(candidate)
        except OSError:  # unreadable or looping entry — cannot be the import source
            continue
    return None


def _run_schedule(args: argparse.Namespace) -> int:
    """Emit an OS-native scheduler unit that runs scan+diff on a cadence (Feature F).

    No daemon and no clock: the unit text comes from a pure generator in
    :mod:`mcpscan.schedule`. Default prints the unit + install guidance to stdout
    and writes nothing; ``--out PATH`` writes the unit (a user-requested write)
    and prints — but NEVER executes — the exact ``launchctl`` / ``systemctl`` /
    ``schtasks`` command, because installing a scheduler is the user's action.
    The scheduled command diffs a fresh scan against a baseline, so the user must
    create that baseline first (disclosed to stderr). No egress anywhere.
    """
    import platform

    from .schedule import (
        DEFAULT_LABEL,
        SERVICE_STEM,
        Cadence,
        ScheduleError,
        SchedulePlan,
        launchd_plist,
        systemd_units,
        windows_task_xml,
    )

    if args.cadence is None:
        print("error: 'schedule' requires --cadence {hourly,daily,weekly}", file=sys.stderr)
        return 2

    cadence = Cadence(args.cadence)
    roots = tuple(str(p.resolve()) for p in (args.root or [Path.cwd()]))
    baseline = (
        args.baseline.resolve()
        if args.baseline is not None
        else Path(roots[0]) / _DEFAULT_BASELINE_NAME
    )
    invocation, pythonpath = _resolve_mcpscan_invocation()
    plan = SchedulePlan(
        invocation=invocation,
        roots=roots,
        baseline=str(baseline),
        cadence=cadence,
        pythonpath=pythonpath,
    )

    print(
        "note: 'schedule' only generates a scheduler unit; it installs and runs "
        "nothing. The scheduled command diffs a fresh scan against a baseline, so "
        f"create it first: mcpscan baseline --out {baseline}",
        file=sys.stderr,
    )
    if pythonpath is not None:
        print(
            "note: mcpscan is not installed on PATH and imports only via this "
            f"source tree, so the unit bakes PYTHONPATH={pythonpath} into the "
            "scheduled command. It breaks if the tree moves; install mcpscan "
            "and re-run 'schedule' for an install-independent unit.",
            file=sys.stderr,
        )

    system = platform.system()
    if system == "Darwin":
        target = _emit_single_unit(
            launchd_plist(plan),
            args.out,
            default_path=Path.home() / "Library" / "LaunchAgents" / f"{DEFAULT_LABEL}.plist",
        )
        install = f"launchctl load {target}"
        instructions = (
            f"install (launchd): copy the plist to {target}, then run the command "
            "below (unload later with 'launchctl unload <path>')."
        )
    elif system == "Linux":
        try:
            timer_text, service_text = systemd_units(plan)
        except ScheduleError as exc:
            # A path that cannot be represented on a unit-file line is refused,
            # not rendered — a half-escaped unit is a directive-injection hole.
            print(f"error: {exc}", file=sys.stderr)
            return 2
        target = _emit_systemd_units(timer_text, service_text, args.out)
        install = f"systemctl --user enable --now {target.name}"
        instructions = (
            "install (systemd --user): copy both units to ~/.config/systemd/user/, "
            "run 'systemctl --user daemon-reload', then the command below."
        )
    elif system == "Windows":
        target = _emit_single_unit(
            windows_task_xml(plan), args.out, default_path=Path(f"{SERVICE_STEM}-task.xml")
        )
        install = f'schtasks /create /tn "{SERVICE_STEM}" /xml {target} /f'
        instructions = (
            "install (Task Scheduler): from an elevated prompt, register the saved "
            "task XML with the command below."
        )
    else:
        print(
            f"error: 'schedule' does not support this platform ({system!r}); supported: "
            "Darwin (launchd), Linux (systemd), Windows (Task Scheduler).",
            file=sys.stderr,
        )
        return 2

    guidance = f"{instructions}\ninstall (run it yourself; schedule never does): {install}\n"
    # Default mode routes guidance to stdout (spec: unit text + instructions to
    # stdout); --out mode already wrote to disk, so guidance is progress → stderr.
    print(guidance, end="", file=sys.stderr if args.out is not None else sys.stdout)
    return 0


def _emit_single_unit(content: str, out: Path | None, *, default_path: Path) -> Path:
    """Write a single unit under ``--out`` or print it; return the install target.

    In write mode the unit lands at ``out`` (owner-only, via ``write_report``) and
    that path is the install target. In print mode the text goes to stdout and the
    conventional ``default_path`` is returned so the install command still names a
    real location.
    """
    from .report.writer import write_report

    if out is not None:
        write_report(out, content)
        print(f"wrote scheduler unit: {out}", file=sys.stderr)
        return out
    print(content, end="" if content.endswith("\n") else "\n")
    return default_path


def _emit_systemd_units(timer_text: str, service_text: str, out: Path | None) -> Path:
    """Write/print the systemd timer+service pair; return the timer install target.

    With ``--out``, the timer is written at ``out`` and the service alongside it
    (``<stem>.service``). Without ``--out``, both units print to stdout under
    labelled headers and the conventional ``mcpscan.timer`` name is returned.
    """
    from .report.writer import write_report
    from .schedule import SERVICE_STEM

    if out is not None:
        service_path = out.with_suffix(".service")
        write_report(out, timer_text)
        write_report(service_path, service_text)
        print(f"wrote scheduler unit: {out}", file=sys.stderr)
        print(f"wrote scheduler unit: {service_path}", file=sys.stderr)
        return out
    print(f"# --- {SERVICE_STEM}.timer ---")
    print(timer_text, end="" if timer_text.endswith("\n") else "\n")
    print(f"# --- {SERVICE_STEM}.service ---")
    print(service_text, end="" if service_text.endswith("\n") else "\n")
    return Path(f"{SERVICE_STEM}.timer")


def _run_selftest(args: argparse.Namespace) -> int:
    """The self-test canary command (Feature C): confirm core detections still fire.

    Runs the real engine over a throwaway, deliberately-misconfigured fixture in a
    temp dir it creates and cleans up, and confirms each stable core finding id
    still appears (plus the exposure classifier). Prints a per-check PASS/FAIL
    line. Exits 0 when every detection fires; exits 1 with a loud "scanner appears
    degraded" message on stderr if any expected finding is missing — the signal
    that the scanner can no longer be trusted. No network; no lasting writes.
    """
    from .selftest import run_selftest

    report = run_selftest()
    for result in report.results:
        status = "PASS" if result.present else "FAIL"
        print(f"[{status}] {result.surface}: {result.expected_id}")

    if report.ok:
        print(f"selftest OK: all {len(report.results)} core detection(s) fired.")
        return 0

    for missing in report.missing:
        print(
            f"scanner appears degraded: expected finding {missing.expected_id} "
            f"did not fire ({missing.surface} surface).",
            file=sys.stderr,
        )
    return 1


def _run_update_datapack(args: argparse.Namespace) -> int:
    """Verify a signed detection data-pack and install it locally (Feature D).

    Opt-in and verify-or-refuse: the pack's detached signature is checked over the
    exact pack bytes (reusing the LAN signature machinery under a dedicated
    ``mcpscan-datapack`` namespace) before anything is written. On success the pack
    is copied to the OS-appropriate local store; later scans pick it up in place of
    the built-in catalogs. On a verification failure nothing is written and the
    command exits non-zero with the reason. No network is contacted — the pack is a
    local file path (a future flag can add URL fetch).
    """
    import os
    import platform

    from .adapters.paths import datapack_store_path
    from .datapack import DataPackError, first_allowed_signer, load_verified_datapack
    from .report.writer import write_report

    if args.pack is None or args.signature is None or args.allowed_signers is None:
        print(
            "error: 'update-datapack' requires --pack, --signature, and --allowed-signers",
            file=sys.stderr,
        )
        return 2

    try:
        pack_bytes = args.pack.read_bytes()  # read once; verified and installed as-is
        signers_text = args.allowed_signers.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"error: cannot read a data-pack input file: {exc}", file=sys.stderr)
        return 2

    operator = args.signer or first_allowed_signer(signers_text)
    if operator is None:
        print(
            "error: cannot determine the signer identity from --allowed-signers; pass --signer ID",
            file=sys.stderr,
        )
        return 2

    store = datapack_store_path(platform.system(), os.environ)
    if store is None:
        print("error: cannot resolve a local data-pack store location for this OS", file=sys.stderr)
        return 2
    store_path = Path(str(store))

    print(
        f"note: 'update-datapack' verifies {args.pack} against {args.allowed_signers} "
        f"(scheme {args.scheme}, signer {operator!r}) and, on success, installs it to "
        f"{store_path}. No network is contacted.",
        file=sys.stderr,
    )

    result = load_verified_datapack(
        args.pack,
        args.signature,
        args.allowed_signers,
        operator=operator,
        scheme=args.scheme,
        pack_bytes=pack_bytes,  # verify exactly the bytes we will install
    )
    if isinstance(result, DataPackError):
        print(f"error: data-pack refused (nothing installed): {result.message}", file=sys.stderr)
        return 1

    store_path.parent.mkdir(parents=True, exist_ok=True)
    # Install the exact verified bytes (valid UTF-8, proven by the successful parse above).
    write_report(store_path, pack_bytes.decode("utf-8"))
    print(
        f"installed data-pack to {store_path} "
        f"(schema {result.schema_version}, {len(result.provider_patterns)} provider pattern(s)).",
        file=sys.stderr,
    )
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

    # "now" is read here, once, and passed into the pure token-store/telemetry
    # checks so no clock is consulted below the CLI layer (determinism guardrail).
    now_epoch: int | None = None
    if args.inspect_token_stores or args.inspect_telemetry:
        from datetime import datetime

        now_epoch = int(datetime.now(UTC).timestamp())
    if args.inspect_token_stores:
        print(
            "note: --inspect-token-stores reads token-store file contents to check "
            "expiry; no token value is stored or printed.",
            file=sys.stderr,
        )
    if args.inspect_process_env:
        print(
            "note: --inspect-process-env reads environment blocks of your own "
            "running agent/MCP processes to detect plaintext secrets; values are "
            "redacted, never stored.",
            file=sys.stderr,
        )
    if args.inspect_telemetry:
        print(
            "note: --inspect-telemetry reads only log-file metadata (existence, "
            "permissions, mtime) to grade logging health; no log contents are read.",
            file=sys.stderr,
        )
    if args.inspect_broker:
        print(
            "note: --inspect-broker reads the Agent Trust Broker manifest "
            "(broker.json) to grade broker posture; it is assessment-only and "
            "never writes to or contacts the broker.",
            file=sys.stderr,
        )

    if args.inspect_live_tools:
        _disclose_live_tools(args)

    report = scan(
        roots=args.root,
        online=args.online,
        inspect_token_stores=args.inspect_token_stores,
        inspect_process_env=args.inspect_process_env,
        inspect_telemetry=args.inspect_telemetry,
        inspect_broker=args.inspect_broker,
        inspect_live_tools=args.inspect_live_tools,
        live_tools_targets=tuple(args.live_tools_target),
        stdio_targets=tuple(args.spawn_stdio),
        container_runtime=args.container_runtime,
        tools_json_targets=tuple(args.tools_json),
        now_epoch=now_epoch,
    )
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

    code = _exit_code(report, args.fail_on)
    _emit_alerts(args, report, kind="scan", gate_failed=bool(code), threshold=args.fail_on)
    return code


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


def _apply_tool_drift_ledger(report: DriftReport, roots: list[Path] | None) -> DriftReport:
    """Waive per-tool drift that a named human accepted in ``.mcpscan-accept.json``.

    "today" is read here, once, so :mod:`mcpscan.acceptance` stays clock-free.
    Ledger warnings go to stderr; a malformed ledger never fails the diff.
    """
    from datetime import datetime

    from .acceptance import apply_tool_drift_acceptances, load_ledgers

    ledger = load_ledgers(roots if roots is not None else [Path.cwd()])
    for warning in ledger.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return apply_tool_drift_acceptances(report, ledger.tool_entries, today=datetime.now(UTC).date())


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


def _emit_alerts(
    args: argparse.Namespace,
    report: object,
    *,
    kind: str,
    gate_failed: bool,
    threshold: str,
) -> None:
    """Push a redacted alert to each requested sink, AFTER rendering (Feature E).

    Opt-in and disclosed: with no ``--emit`` sink selected this returns before it
    imports the emit layer or touches any file/socket — the default run alerts
    nowhere. ``generated_at`` is read here, once (the CLI is the only clock), and
    handed to the pure payload builder. The webhook's egress destination is
    disclosed to stderr before the POST fires; the payload carries no secret
    value, only an 8-hex fingerprint.
    """
    sinks: list[str] = list(args.emit or [])
    if args.emit_syslog and "syslog" not in sinks:
        sinks.append("syslog")
    if not sinks:
        return

    from datetime import datetime
    from urllib.parse import urlsplit

    from .emit import build_emit_payload, emit_ndjson, emit_syslog, emit_webhook

    generated_at = datetime.now(UTC).isoformat()
    payload = build_emit_payload(
        report,  # type: ignore[arg-type]  # Report for scan, DriftReport for diff
        kind=kind,
        generated_at=generated_at,
        gate_failed=gate_failed,
        threshold=threshold,
    )

    if "ndjson" in sinks:
        if args.emit_ndjson_path is None:
            print("error: --emit ndjson requires --emit-ndjson-path PATH", file=sys.stderr)
        else:
            emit_ndjson(args.emit_ndjson_path, payload)
            print(f"emitted {kind} alert (ndjson) to {args.emit_ndjson_path}", file=sys.stderr)
    if "webhook" in sinks:
        if args.emit_webhook_url is None:
            print("error: --emit webhook requires --emit-webhook-url URL", file=sys.stderr)
        else:
            host = urlsplit(args.emit_webhook_url).netloc or args.emit_webhook_url
            print(
                f"note: --emit webhook POSTs a REDACTED findings summary to {host}; "
                "no secret values are sent.",
                file=sys.stderr,
            )
            emit_webhook(args.emit_webhook_url, payload)
    if "syslog" in sinks:
        emit_syslog(payload)
        print(f"emitted {kind} alert (syslog).", file=sys.stderr)


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
