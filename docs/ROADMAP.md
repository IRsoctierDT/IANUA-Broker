# IANUA-Broker build spawn roadmap

Living map from adversarial review (2026-09-10) and design residuals into
buildable slices. Prefer code/PRs over issue-only tracking.

## Shipped in v1.6.0

| ID | Change |
|---|---|
| `R-BROKER-EVIDENCE` | `broker.json` good postures / fronts require `evidence.expect_tip` + `expect_tip_hash`; optional `chain_path` tip verify |
| `R-WRAPPER-PATH` | `ianua-atb` wrapper must be path-qualified (anti-PATH spoof) |
| `R-INCOMPLETE-CAP` | `inspection_incomplete` servers grade-capped at **C** |
| `R-BASELINE-SIG-CI` | `--require-baseline-signature` + CI dogfood job that signs/verifies |
| `R-ROADMAP` | This file |

## Spawn queue

| ID | Pri | MVP |
|---|---|---|
| `R-LIVE-TOOLS` | P1 | Opt-in `--inspect-live-tools`: loopback `tools/list` only, disclosed egress-to-loopback, risk banner |
| `R-STATUS-SYNC` | P1 | Keep `STATUS.yaml` dated with each release-please bump |
| `R-ATB-TIP-EXPORT` | P0 follow | agent-trust-broker writes tip into `broker.json` evidence automatically |
| `R-EXTRAS-SPLIT` | P2 | Optional extras: `graph`, `lan` install profiles |
| `R-NAME-CLARITY` | P2 | README hierarchy: scanner vs Agent Trust Broker |

## Fenced

- Merging mcpscan with ATB runtime (ADR-17)
- Silent online egress
- Auto-fix of credentials/pinning
