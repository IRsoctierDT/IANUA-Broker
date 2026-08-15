# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Adversarial test battery — the tool under attack, not the tool under test.

The rest of ``tests/`` asks "does this check fire on the input it was written
for?". This package asks the opposite question: **what does an attacker who
controls the input do to the scanner?**

That input is not hypothetical. A ``.mcp.json`` inside a repository you just
cloned, an ``.env`` a dependency dropped in a project root, a broker manifest, a
baseline in CI, a data-pack from a refresh channel, a banner from a LAN host —
every one of them is authored by someone other than the operator, and all of
them are read by this tool. The battery holds those surfaces to four invariants:

1. **Availability** — hostile input degrades to a finding. It never crashes,
   never hangs, never exhausts memory (SPEC NFR-S3, and the DoS row of the §8
   threat model).
2. **Non-evasion** — hostile input cannot make the scanner go quiet. A surface
   that could not be inspected is *reported as un-inspected*; a gate cannot be
   silenced by a file the attacker plants (FR-C1, the acceptance ledger's
   guardrails).
3. **Report integrity** — nothing the scanner prints or writes can be forged,
   escaped, or injected by the strings it quotes: no terminal escape, no HTML
   script, no SARIF/DOT/unit-file break-out (FR-R*, NFR-A11Y).
4. **Confidentiality** — no raw secret reaches any sink, on any path, however
   the secret is shaped (FR-R4/NFR-SEC2, architecture R1); and no hostile input
   induces egress or an unrequested write (NFR-SEC1, FR-R6).

Modules map one-to-one onto attacker objectives; see ``docs/ADVERSARIAL_TESTS.md``
for the objective → module → requirement table. Shared hostile payloads live in
:mod:`tests.adversarial.corpus` so a new payload is exercised everywhere at once.

Every test here must be deterministic and offline. Nothing in this package
contacts a network, writes outside ``tmp_path``, or depends on wall-clock time.
"""
