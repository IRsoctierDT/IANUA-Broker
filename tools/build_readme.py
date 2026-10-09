# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the factual sections of README.md from their sources of truth.

README sections wrapped in::

    <!-- BEGIN GENERATED: name -->
    ...
    <!-- END GENERATED: name -->

are owned by this script; everything else stays hand-written. Each section is
rendered from the code or data it describes, so the README cannot fall behind a
merged change:

==============  ============================================================
section         source of truth
==============  ============================================================
``release``     ``[project].version`` in ``pyproject.toml``
``options``     the CLI's own argument parser (``mcpscan.cli.build_parser``)
``checks``      the atlas framework mappings (``mcpscan.atlas.MAPPINGS``)
==============  ============================================================

Usage::

    python tools/build_readme.py          # rewrite README.md in place
    python tools/build_readme.py --check  # exit 1 if README.md is stale (CI)

Stdlib only and offline. Fails closed: a missing or duplicated marker is an
error, never a silently skipped section.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

_MARKER = re.compile(
    r"(<!-- BEGIN GENERATED: (?P<name>[a-z-]+) -->\n)(?P<body>.*?)(<!-- END GENERATED: (?P=name) -->)",
    re.DOTALL,
)
# Every marker token, matched or not — catches stray and unbalanced markers.
_ANY_MARKER = re.compile(r"<!-- (BEGIN|END) GENERATED: ([^>]*?) -->")


def _cell(text: str) -> str:
    """Collapse whitespace and escape a value for a Markdown table cell."""
    return " ".join(text.split()).replace("|", "\\|")


def render_release() -> str:
    """The current release line, from ``pyproject.toml``."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = data["project"]["version"]
    # The trailing annotation lets release-please's generic updater bump this
    # line in the same release PR that bumps pyproject.toml (extra-files in
    # release-please-config.json), so a release never leaves the README stale.
    return (
        f"**Current release: v{version}** "
        "([changelog](CHANGELOG.md), [PyPI](https://pypi.org/project/ianua-broker/))."
        " <!-- x-release-please-version -->\n"
    )


def render_options() -> str:
    """Every command and option, straight from the argument parser."""
    from mcpscan.cli import build_parser

    parser = build_parser()
    formatter = parser._get_formatter()
    rows = ["| Option | Description |", "|---|---|"]
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction) or action.help == argparse.SUPPRESS:
            continue
        if action.option_strings:
            name = ", ".join(action.option_strings)
            if action.nargs != 0:
                metavar = action.metavar or action.dest.upper()
                name = f"{name} {metavar}"
        else:
            name = "COMMAND"
            if action.choices:
                name += " (" + " · ".join(str(c) for c in action.choices) + ")"
        help_text = formatter._expand_help(action) if action.help else ""
        rows.append(f"| `{_cell(name)}` | {_cell(help_text)} |")
    return "\n".join(rows) + "\n"


def render_checks() -> str:
    """Every check id the scanner can emit, with its framework citations."""
    from mcpscan.atlas import MAPPINGS, Framework, framework_label

    frameworks = list(Framework)
    header = "| Check | " + " | ".join(framework_label(f) for f in frameworks) + " |"
    rows = [header, "|---" * (len(frameworks) + 1) + "|"]
    for check_id in sorted(MAPPINGS):
        cells = []
        for framework in frameworks:
            refs = [r.ref for r in MAPPINGS[check_id] if r.framework is framework]
            cells.append(", ".join(refs) or "—")
        rows.append(f"| `{check_id}` | " + " | ".join(cells) + " |")
    return "\n".join(rows) + "\n"


GENERATORS: dict[str, Callable[[], str]] = {
    "release": render_release,
    "options": render_options,
    "checks": render_checks,
}


def regenerate(text: str) -> tuple[str, list[str]]:
    """Return ``(new README text, names of sections that changed)``.

    Raises:
        ValueError: a generator has no marker, a marker is duplicated, or the
            README names a section this script does not own.
    """
    found = [m.group("name") for m in _MARKER.finditer(text)]
    unknown = sorted(set(found) - set(GENERATORS))
    missing = sorted(set(GENERATORS) - set(found))
    duplicated = sorted({n for n in found if found.count(n) > 1})
    if unknown or missing or duplicated:
        raise ValueError(
            f"README markers invalid: missing={missing} unknown={unknown} duplicated={duplicated}"
        )
    tokens = len(_ANY_MARKER.findall(text))
    if tokens != 2 * len(found):
        raise ValueError(
            f"README has {tokens - 2 * len(found)} stray or unbalanced generated-section marker(s)"
        )
    changed: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        body = GENERATORS[name]()
        if body != match.group("body"):
            changed.append(name)
        return match.group(1) + body + match.group(4)

    return _MARKER.sub(replace, text), changed


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if README.md is stale (no write)"
    )
    args = parser.parse_args(argv)
    text = README.read_text(encoding="utf-8")
    try:
        new_text, changed = regenerate(text)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.check:
        if changed:
            print(
                "README.md is stale in generated section(s): "
                + ", ".join(changed)
                + "\nFix: python tools/build_readme.py",
                file=sys.stderr,
            )
            return 1
        print("README.md generated sections are up to date.")
        return 0
    if changed:
        README.write_text(new_text, encoding="utf-8")
        print("updated README.md section(s): " + ", ".join(changed))
    else:
        print("README.md already up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
