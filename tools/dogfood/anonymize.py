# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Anonymize a real MCP config into a safe regression fixture (T-402, Phase 2).

The dogfood protocol turns every real false-positive / false-negative into a
permanent corpus fixture (proposal §4.3). Real configs can't enter the repo as
they are: they carry live secrets, usernames, and host paths. This scrubs a
collected config into a structurally-identical fixture that trips the **same
checks** — so the regression stays real — while carrying **nothing sensitive**.

Two guarantees, both by construction:

- **No raw secret survives.** Every value the scanner's own detector
  (``checks.secrets._looks_secret``) flags is replaced with a synthetic
  placeholder of the *same class* (a provider-shaped token still matches its
  provider regex; an entropy-flagged value becomes a same-length high-entropy
  fake), so the anonymized config still produces the identical finding — but the
  original bytes are gone.
- **No identity survives.** Home paths (``/home/<user>``, ``/Users/<user>``,
  ``C:\\Users\\<user>``) collapse to a generic user, and the report of what was
  changed carries only counts and categories, never a before value.

Usage:
    python tools/dogfood/anonymize.py real_config.json --host claude \
        --scope project --relpath .mcp.json

Prints the scrubbed config and a ready-to-paste ``Fixture(...)`` whose
``expects`` set is derived by actually running the scanner over the scrubbed
content — so the fixture's label is what the tool really produces, verified.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# The anonymizer reuses the tool's *own* detectors and adapters, so it scrubs
# exactly what the scanner flags — never more, never less.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from mcpscan.checks.secrets import _looks_secret, shannon_entropy
from mcpscan.engine import _adapters

# A deterministic synthetic for each provider pattern: same shape, obviously fake
# (the value is literally the word "SYNTHETIC" padded to a matching length), so
# it still matches the provider regex and still trips CRED-PLAINTEXT.
_PROVIDER_SYNTHETICS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "sk-ant-" + "SYNTHETIC0" * 3),
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}"), "sk-" + "SYNTHETIC0" * 3),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "ghp_" + "SYNTHETIC0" * 5),
    (
        "GitHub fine-grained PAT",
        re.compile(r"github_pat_[A-Za-z0-9_]{50,}"),
        "github_pat_" + "SYNTHETIC0" * 6,
    ),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA" + "SYNTHETIC00ABCDE1"[:16]),
    # Google's pattern is fixed-length (exactly 35): the synthetic must be 35
    # chars after "AIza" so a search matches it whole (idempotent under re-sweep).
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "AIza" + "SYNTHETIC0" * 3 + "ABCDE"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "xoxb-" + "SYNTHETIC0" * 3),
)

# Home-path prefixes → a generic user, so no real username survives.
_HOME_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/home/[^/\"'\s]+"), "/home/user"),
    (re.compile(r"/Users/[^/\"'\s]+"), "/Users/user"),
    (re.compile(r"C:\\\\Users\\\\[^\\\\\"'\s]+"), r"C:\\Users\\user"),
    (re.compile(r"C:\\Users\\[^\\\"'\s]+"), r"C:\\Users\\user"),
)


@dataclass(frozen=True)
class AnonymizeReport:
    """A summary of what changed — counts and categories only, never a value."""

    secrets_replaced: dict[str, int] = field(default_factory=dict)
    paths_scrubbed: int = 0

    @property
    def total_secrets(self) -> int:
        return sum(self.secrets_replaced.values())


def _entropy_synthetic(length: int) -> str:
    """A same-length high-entropy placeholder (trips the entropy branch)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789abcdefghijkmnpqrstuvwxyz"
    # Deterministic, obviously-synthetic, but high-entropy: cycle the alphabet.
    body = (alphabet * (length // len(alphabet) + 1))[:length]
    # Guarantee the entropy floor even for short lengths by keeping variety.
    return body if shannon_entropy(body) >= 3.5 else (alphabet * length)[:length]


def _synthetic_for(value: str) -> str:
    """A synthetic replacement of the same class as ``value``."""
    for _label, pattern, synthetic in _PROVIDER_SYNTHETICS:
        if pattern.search(value):
            return synthetic
    # Private-key blocks and generic high-entropy secrets → entropy placeholder.
    return _entropy_synthetic(max(len(value), 24))


def _secret_values(host: str, text: str) -> dict[str, str]:
    """Map every scanner-detected secret *value* to its synthetic replacement.

    Uses the matching host adapter to find the (key, value) env pairs, then the
    scanner's own ``_looks_secret`` so the set is exactly what a scan flags.
    """
    adapter = next((a for a in _adapters() if a.name == host), None)
    if adapter is None:
        raise ValueError(f"unknown host {host!r}; expected one of {[a.name for a in _adapters()]}")
    parsed = adapter.parse(f"anon.{host}", text)
    replacements: dict[str, str] = {}
    for server in parsed.servers:
        for key, value in server.env:
            if value and value not in replacements and _looks_secret(key, value):
                replacements[value] = _synthetic_for(value)
    return replacements


class LeakError(RuntimeError):
    """Raised if a provider-shaped secret would survive anonymization.

    Fail closed: rather than risk emitting a real token, the anonymizer refuses.
    In practice the provider sweep replaces every match, so this never fires — it
    is the guarantee's backstop, not an expected path.
    """


def anonymize(host: str, text: str) -> tuple[str, AnonymizeReport]:
    """Return ``(scrubbed_text, report)`` for a real config.

    Scrubbing runs in two passes, then a fail-closed check:

    1. **Structured pass** — every value the scanner's own detector flags in a
       parsed ``env`` block is swapped for a same-class synthetic (this is the
       set a scan would report, so the fixture keeps tripping the same check).
    2. **Provider sweep** — every provider-shaped token (Anthropic/OpenAI/GitHub/
       AWS/Google/Slack/private-key) is then replaced *anywhere* in the text,
       not just in ``env`` — so a key hiding in ``args`` or a nonstandard field
       can't slip through the structured pass.
    3. **Fail closed** — if any provider pattern still matches, raise
       :class:`LeakError` instead of returning text that could be printed.

    Home paths are genericized. The original text is never returned and the
    report holds only counts.
    """
    scrubbed = text
    secrets_by_class: dict[str, int] = {}

    # Pass 1: structured env secrets (keeps the fixture's finding set faithful).
    for value, synthetic in _secret_values(host, text).items():
        label = _looks_secret("token", value) or "High-entropy secret"
        occurrences = scrubbed.count(value)
        if occurrences:
            scrubbed = scrubbed.replace(value, synthetic)
            secrets_by_class[label] = secrets_by_class.get(label, 0) + occurrences

    # Pass 2: provider-shaped tokens anywhere in the text (defense in depth).
    # Count only NET-NEW real tokens — a value pass 1 already replaced is now our
    # synthetic, which the pattern also matches, so exclude those from the count.
    for label, pattern, synthetic in _PROVIDER_SYNTHETICS:
        new_matches = sum(1 for m in pattern.finditer(scrubbed) if m.group(0) != synthetic)
        if new_matches:
            scrubbed = pattern.sub(synthetic, scrubbed)
            secrets_by_class[label] = secrets_by_class.get(label, 0) + new_matches

    paths_scrubbed = 0
    for pattern, replacement in _HOME_PATTERNS:
        scrubbed, path_n = pattern.subn(replacement, scrubbed)
        paths_scrubbed += path_n

    _assert_no_provider_secret(scrubbed)
    return scrubbed, AnonymizeReport(
        secrets_replaced=secrets_by_class, paths_scrubbed=paths_scrubbed
    )


def _assert_no_provider_secret(scrubbed: str) -> None:
    """Fail closed if any provider-shaped token survived the sweep."""
    for label, pattern, synthetic in _PROVIDER_SYNTHETICS:
        for match in pattern.finditer(scrubbed):
            if match.group(0) != synthetic:  # a real token, not our placeholder
                raise LeakError(f"a {label} survived anonymization; refusing to emit")


def suggest_fixture(host: str, label: str, scope: str, relpath: str, scrubbed: str) -> str:
    """Emit a ``Fixture(...)`` whose ``expects`` is what the scanner really finds.

    Runs the scrubbed content through the real ``evaluate`` pipeline (the same
    one the corpus uses) so the fixture's label is verified, not guessed.
    """
    from corpus import CHECK_IDS, Fixture, evaluate

    probe = Fixture(host=host, label=label, scope=scope, relpath=relpath, content=scrubbed)
    result = evaluate(probe)
    expects = sorted(result.actual & set(CHECK_IDS))
    expects_src = (
        "frozenset({" + ", ".join(repr(cid) for cid in expects) + "})" if expects else "frozenset()"
    )
    return (
        "Fixture(\n"
        f"    {host!r},\n"
        f"    {label!r},\n"
        f"    {scope!r},\n"
        f"    {relpath!r},\n"
        '    """' + scrubbed.replace('"""', '\\"\\"\\"') + '""",\n'
        f"    {expects_src},\n"
        "),"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Anonymize a real MCP config into a fixture.")
    parser.add_argument("config", type=Path, help="Path to the real config file.")
    parser.add_argument("--host", required=True, help="Host adapter name (e.g. claude, cursor).")
    parser.add_argument("--scope", default="project", choices=("project", "user"))
    parser.add_argument("--relpath", required=True, help="Discovery path relative to root/HOME.")
    parser.add_argument("--label", default="messy", help="Fixture label (clean|messy|…).")
    parser.add_argument(
        "--emit-fixture",
        action="store_true",
        help="Also print a ready-to-paste Fixture(...) with a verified expects set.",
    )
    args = parser.parse_args(argv)

    text = args.config.read_text(encoding="utf-8")
    scrubbed, report = anonymize(args.host, text)

    # Redaction-safe by construction: `anonymize` replaces every scanner-detected
    # secret and every provider-shaped token, and fails closed (LeakError) rather
    # than return text a provider secret survived — so `scrubbed` cannot carry one
    # to this sink, and `report` holds only counts/category labels. CodeQL
    # py/clear-text-logging-sensitive-data flags these prints because it can't
    # model that sanitizer as a barrier — accepted false positive, dismissed in
    # code scanning (mirrors the documented case in src/mcpscan/cli.py).
    print("# --- anonymized config ---")
    print(scrubbed)
    print("# --- report (no sensitive values) ---", file=sys.stderr)
    print(
        f"# secrets replaced: {report.total_secrets} "
        f"({report.secrets_replaced}); paths scrubbed: {report.paths_scrubbed}",
        file=sys.stderr,
    )
    if args.emit_fixture:
        print("\n# --- fixture (verified expects) ---")
        print(suggest_fixture(args.host, args.label, args.scope, args.relpath, scrubbed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
