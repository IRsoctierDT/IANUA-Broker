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

## Landed (unreleased)

| ID | Change |
|---|---|
| `R-LIVE-TOOLS` | Opt-in `--inspect-live-tools` + `--live-tools-target`: loopback-only MCP handshake and paginated `tools/list` (JSON + SSE, session ids), hardened (no proxy, no redirects, no credentials, size/depth/count/deadline caps); `LIVE-TOOL-*` checks; canonical per-tool and manifest digests; manifest digest as `tool_identity` so `baseline`/`diff` flag rug pulls; stdlib loopback MCP fixture server in CI |

## Direction: live manifests, skill content, server source (2026-10-09)

Owner-set direction after the 2026 scanner-landscape research
(IANUA `research/2026-10-09-security-scanner-landscape.md`). Each slice stays
stdlib, offline by default, deterministic, and fail-closed.

| ID | Pri | MVP |
|---|---|---|
| `R-LIVE-TOOL-DRIFT` | P1 — **in progress** | Landed: per-tool drift facts and causes (`tool_added/removed/desc_changed/schema_changed/annot_relaxed/annot_tightened`) and a named-human ledger that accepts one tool version by digest. Remaining: SARIF before/after; `baseline --import-mcp-lock` (mcpseal), pending verification of mcpseal's lockfile format against its source |
| `R-LIVE-TOOLS-JSON` | P1 | `--tools-json FILE` offline fixture input (shared by flow analysis, conformance and bench) |
| `R-LIVE-STDIO` | P1 — **landed** | `--spawn-stdio NAME=IMAGE@sha256:…` + `--container-runtime`: operator-supplied, digest-pinned image run in the ADR-18 sandbox; shared bounded handshake with the HTTP path; real-container isolation proven in CI. Next: `baseline --import-mcp-lock` (mcpseal), now that stdio servers can be inspected |
| `R-SKILL-CONTENT` | P2 | Static checks over `SKILL.md`, `.claude/agents`, `.claude/commands`, plugin manifests and hooks (hooks are shell at event time) |
| `R-SERVER-SOURCE` | P2 | Lightweight, deterministic source checks of locally installed MCP servers (shell-exec sinks, path handling, SSRF-prone fetches) — scoped to what stdlib `ast` can prove |

## Spawn queue

| ID | Pri | MVP |
|---|---|---|
| `R-STATUS-SYNC` | P1 | Keep `STATUS.yaml` dated with each release-please bump |
| `R-ATB-TIP-EXPORT` | P0 follow | agent-trust-broker writes tip into `broker.json` evidence automatically |
| `R-EXTRAS-SPLIT` | P2 | Optional extras: `graph`, `lan` install profiles |
| `R-NAME-CLARITY` | P2 | README hierarchy: scanner vs Agent Trust Broker |

## Fenced

- Merging mcpscan with ATB runtime (ADR-17)
- Silent online egress
- Auto-fix of credentials/pinning
