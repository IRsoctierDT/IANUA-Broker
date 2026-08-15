# Adversarial Test Battery

> **Scope:** `tests/adversarial/` — 716 tests that treat IANUA-Broker as the
> target rather than the tool. Companion to [`SPEC.md`](./SPEC.md) §8 (threat
> model) and the NFRs it references.

## Why a separate battery

The rest of `tests/` asks *"does this check fire on the input it was written
for?"*. That is necessary and it is not the same question as *"what happens when
the input is chosen by an attacker?"*.

For this tool the second question is not hypothetical. Almost everything it
reads is authored by someone other than the operator:

| Surface | Who writes it |
|---|---|
| `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, `.zed/settings.json` | whoever wrote the repository you cloned |
| `.env` in a project root | any dependency, generator, or teammate |
| `broker.json` | the broker deployment |
| `.mcpscan-accept.json` | anyone with commit access |
| a baseline in CI | anyone who can push |
| a detection data-pack | the refresh channel |
| a LAN banner | the remote host |

A scanner that mishandles any of them is worse than no scanner: it produces a
signed-looking artifact that says everything is fine.

## The four invariants

Every test in the battery exists to defend one of these.

| # | Invariant | Traces to |
|---|---|---|
| 1 | **Availability** — hostile input degrades to a finding: no crash, no hang, no memory blow-up | NFR-S3, SPEC §8 "Denial of service" |
| 2 | **Non-evasion** — hostile input cannot make the scanner go quiet; an un-inspected surface is *reported as un-inspected* | FR-C1, SPEC §8 "Tampering" |
| 3 | **Report integrity** — nothing the tool prints or writes can be forged or escaped by the strings it quotes | FR-R3/R4/R6, NFR-A11Y |
| 4 | **Confidentiality & containment** — no raw secret reaches any sink; no hostile input induces egress or an unrequested write | FR-R4, NFR-SEC1, NFR-SEC2, NFR-SEC3 |

## Module map

| Module | Attacker objective | Tests | Invariant |
|---|---|---|---|
| `corpus.py` | *(shared payloads — not a test module)* | — | — |
| `test_parser_robustness.py` | Crash the scanner with the file it was asked to read | 389 | 1 |
| `test_file_surface.py` | Attack through the filesystem: FIFO, symlink loop, escape, device, oversize | 15 | 1, 4 |
| `test_report_integrity.py` | Make the report lie — terminal repaint, XSS, SARIF/DOT/unit-file break-out | 138 | 3 |
| `test_secret_leakage.py` | Get the scanner to hand back the secrets it found | 67 | 4 |
| `test_evasion.py` | Make the scanner go quiet about something real | 37 | 2 |
| `test_resource_limits.py` | Spend the scanner's time and memory instead of crashing it | 11 | 1 |
| `test_isolation.py` | Use the scanner as a side effect — make it talk, or make it write | 10 | 4 |
| `test_detection_under_attack.py` | Hide something real from a scanner that is otherwise working | 36 | 2 |
| `test_end_to_end.py` | All of the above, through the CLI, against one hostile repository | 13 | 1–4 |

The shared corpus (`corpus.py`) means an attack primitive is added once and
swept across every module that consumes it — control characters, invisible and
bidirectional Unicode, markup and format break-outs, prompt-injection phrases,
traversal paths, deep nesting, and structurally-valid fake credentials.

## What the battery found

Every item below was a real defect in `main`, found by writing the test first.
All are fixed in the same change as the battery.

| # | Defect | Effect | Fix |
|---|---|---|---|
| 1 | `RecursionError` on deeply-nested JSON in **7 host adapters** plus the acceptance ledger, data-pack, baseline, token-store, and fix planner | ~400 KB of `[[[[…]]]]` — far under the 5 MB cap — crashed the whole scan. `RecursionError` is a `RuntimeError`, so `except ValueError` did not catch it | Shared `adapters.base.decode_config` boundary; explicit guards at every other `json.loads` over untrusted text |
| 2 | `io_safe` **hung forever** on a non-regular file | A `.mcp.json` planted as a FIFO reports `st_size == 0`, so the size cap could not see it, and `read_text` blocked with no writer | Reject non-regular files by type, before reading |
| 3 | `io_safe` raised a bare `RuntimeError` on a **symlink loop** | Path resolution failed before any invariant was checked; callers catch `SafeReadError` only, so a two-symlink trap crashed the scan | Wrap resolution failures as `FileAccessError` |
| 4 | An **unparseable or unreadable config was silently dropped** | Grade A and exit 0 over a surface never inspected — the cheapest possible evasion, since MCP hosts are more tolerant parsers than `json.loads` | New `CONFIG-UNREADABLE` finding (MEDIUM) riding `inspection_incomplete`, satisfying FR-C1's acceptance criterion |
| 5 | **Terminal escape injection** in every terminal-facing renderer | A config value could clear the screen, repaint a CRITICAL line, or forge a whole `▶ server [grade A]` row in the operator's report | `report.inert_text` — control, C1, and bidi characters become visible `\uXXXX` escapes; applied in the scan, atlas, drift, inventory, and graph renderers |
| 6 | `lan.sanitize_remote` passed **bidi and zero-width** characters through | The module that exists to make remote bytes inert left intact the exact codepoints the scanner flags as tool-poisoning in configs | Strip the shared `HIDDEN_CODEPOINTS` catalog |
| 7 | `lan.sanitize_remote` passed **C1 controls** through | `ch >= " "` admits U+0080–U+009F, including U+009B — the 8-bit CSI a UTF-8 terminal still acts on — despite the comment claiming C0/C1 | Explicit C1 range check |
| 8 | **systemd unit-file injection** via a newline in a scanned path | `shlex.quote` protects a *shell*; systemd ends the `ExecStart` directive at the newline and reads the rest as directives, so `ExecStartPost=` was honoured | `ScheduleError` refusal for control characters; the CLI reports it and exits 2 |
| 9 | Continue's YAML adapter raised a bare `ValueError` | PyYAML's scalar constructors raise `ValueError`, not `YAMLError` — an integer past CPython's 4300-digit limit escaped the handler | Catch `ValueError` alongside `YAMLError` |

| 10 | The **HTML report was escaped but not inert** | `html.escape` stops script injection and stops there — a browser still honours a bidi override or a zero-width joiner, so a server name could reorder the text a reviewer reads in the artifact most likely to be forwarded to one | `_safe()` defangs via `inert_text` *before* escaping, so the HTML and terminal renderers agree on what "inert" means |

Two invariants were attacked and **held** with no change needed: HTML *markup*
escaping (no XSS survived any payload) and the JSONC comment stripper's
string-awareness (no parser differential across 13 hand-picked cases).

## Scope statements

Some evasions are out of scope by design. The battery pins them as tests with
the reasoning attached, so "why didn't it catch X" has a written answer and a
future narrowing of a compensating control is caught:

- **Encoded secrets are not decoded.** Detection is pattern + entropy over
  literal values. Chasing base64 means chasing every encoding, at a false-positive
  cost that outruns the coverage gained.
- **A secret split by an invisible character evades the provider pattern** — no
  regex survives arbitrary insertion — **but the insertion itself is reported**
  by `TOOL-HIDDEN-UNICODE` on the same field. That pairing is the actual
  control, and `test_detection_under_attack.py` guards it.
- **Paraphrased prompt injection is not caught.** The phrase list is curated for
  a near-zero false-positive rate; fuzzy matching would fire on ordinary
  READMEs.
- **The baseline digest detects corruption, not a motivated editor.** It is a
  hash of the facts, not a MAC — anyone who can rewrite the file can recompute
  it. A repository where an attacker rewrites committed files has a larger
  problem than drift.
- **A signed data-pack is trusted to define detection.** A pack with no provider
  patterns detects nothing; the control is the signature and the owner-only
  store, not content inspection. The verify-or-refuse path is tested instead.

## Conventions

- **Deterministic and offline.** No test contacts a network, writes outside
  `tmp_path`, or reads a clock.
- **Non-vacuity.** Leak sweeps assert the secret was *detected* before asserting
  it did not leak; an evasion test that stopped detecting anything would
  otherwise pass trivially.
- **Time bounds, not benchmarks.** Resource tests are set at roughly 20x observed
  cost — enough to catch a complexity-class regression, not enough to flake on a
  slow runner. One test asserts a *ratio* rather than an absolute, which is what
  actually separates "slow machine" from "accidental quadratic".
- **Liveness over patience.** A potentially-blocking read runs on a daemon thread
  with a deadline, so a hang fails the test instead of stalling the suite.
- **Payloads as escapes.** Invisible and bidirectional characters are written as
  `"\u202e"`, never as literals — a source file carrying real bidi overrides is
  the attack it is testing for.

## Running it

```sh
pytest tests/adversarial                 # the battery alone (~5s)
pytest tests/adversarial -k evasion      # one objective
pytest                                   # everything, battery included
```

The battery runs in the standard CI job — it is not opt-in. Adding a payload to
`corpus.py` extends every sweep that consumes it, which is the intended way to
grow this: attack primitives are shared, assertions are per-objective.
