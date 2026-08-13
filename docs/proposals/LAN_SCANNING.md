# Proposal — Authorized-LAN scanning (`mcpscan lan`)

**Status:** **Accepted for v1.0, with enhancements** (operator review 2026-07-10;
sub-decisions resolved §9) · **Supersedes the "later" clause of** ADR-1 ·
**Relates to** FR-D*, NFR-SEC1, threat model §8

> **Governing principle (operator-set):** *LAN scanning discovers exposure; it
> never converts discovery into authority.* The feature is assessment-only,
> read-only, exact-target-only, and inert without explicit, attested
> authorization. Nothing here changes the default `mcpscan scan` behavior.

This revision folds in the operator's five required enhancements: a signed,
cryptographically-scoped authorization manifest with a hashed audit record
(§3.1), human-vs-agent invocation controls (§3.2), a hard prohibition on
discovery expansion (§3.3), immutable operational budgets (§3.4), and
hostile-by-default handling of every remote response (§3.5).

---

## 1. Why (unchanged)

An MCP server bound to `0.0.0.0` on a teammate's laptop, a shared dev box, or a
CI runner is reachable across the LAN/VPC — often unauthenticated, often exposing
shell/exec-class tools. An authorized operator sweeping **hosts they own** should
be able to detect that. The whole design exists to enable exactly that and
nothing broader.

## 2. Non-negotiable constraints

1. **Off by default, always.** Plain `mcpscan scan` stays byte-for-byte
   localhost-only. LAN lives in a **separate `mcpscan lan` subcommand** so the
   localhost path can never grow a LAN branch by accident.
2. **Explicit targets only.** Agents get exact hosts / `/32`; a human may add an
   explicit, budget-capped CIDR. **No implicit expansion of any kind, ever**
   (§3.3) — every target is named or an explicitly-typed range.
3. **Attested + signed authorization**, recorded as an immutable audit record
   (§3.1).
4. **Least-intrusive probe only** — TCP connect + the same minimal MCP/HTTP
   handshake the loopback probe uses. No auth attempts, no payloads, no banner
   brute-forcing, no port sweeping beyond the manifest's explicit port list.
5. **Private-address default; public = hard denial** unless an enterprise policy
   file explicitly enables it (not a mere flag).
6. **Exposure-only findings.** We never read a remote filesystem, so no
   credential / pinning / tool-scope checks run against remote hosts.
7. **Remote responses are hostile** and are sanitized before they touch a report
   or any LLM context (§3.5).

If any of these cannot hold, we do not ship.

## 3. Design

### 3.1 Signed authorization manifest + hashed audit record

Authorization is a **manifest file**, not a flag. Canonical format is **TOML**
(parsed with stdlib `tomllib` — no new dependency; the earlier YAML sketch is
avoided precisely to keep the tool stdlib-only):

```toml
authorization_id = "ENG-2026-0710"
operator         = "j.doe@example.com"
expires_at       = "2026-07-10T23:59:59Z"   # probes after this instant are refused
targets          = ["192.168.10.20/32"]     # exact hosts / /32 only
ports            = [3000, 8000, 8080]        # explicit; no default port sweep
```

- The manifest is **signed**; mcpscan verifies a detached signature before any
  packet is sent, via a **pluggable verifier** — the manifest declares the scheme
  and both are supported (operator decision 2026-07-10):
  - **`scheme = "ssh"` (default)** — `ssh-keygen -Y verify` against an
    allowed-signers file. Reuses the operator's existing SSH keypair, ubiquitous,
    **no Python crypto dependency**. Works out of the box.
  - **`scheme = "ed25519"` (optional)** — verified with a vetted asymmetric
    library, installed only via the `[crypto]` extra
    (`pip install ianua-broker[crypto]`). For orgs standardizing on
    library-based signing. Absent the extra, an `ed25519` manifest is refused
    with a clear "install the crypto extra" message — never silently downgraded.

  The default install stays stdlib-only; the crypto path is strictly opt-in.
- mcpscan computes the manifest's **SHA-256** and writes an **immutable audit
  record** for every run: `{manifest_sha256, authorization_id, operator,
  tool_version, utc_timestamp, exact_argv, resolved_targets, results_digest}`.
  The record is emitted to the report and to an append-only local audit log.
- `expires_at` is enforced; an expired manifest is a hard refusal.
- A probe fires **only** for a `(target, port)` pair explicitly present in the
  verified manifest. Anything else is refused, loudly.

### 3.2 Human vs agent invocation

`--invoker human | agent` (no default — must be stated):

| | `--invoker human` | `--invoker agent` |
|---|---|---|
| Authorization | signed manifest **or** interactive typed confirmation | signed manifest **required**; no interactive path |
| Ambiguity (unresolvable scope/expiry/signature) | prompt to clarify | **non-interactive hard denial** — never prompt, never guess |
| Rate/budget ceilings | standard (§3.4) | **tightened** (lower concurrency, longer cooldowns, smaller host cap) |
| CIDR | exact IPs **or** explicit budget-capped `/30`–`/24` (with an extra confirmation) | **exact IPs / `/32` only, ever** |

This directly answers the autonomy risk: an agent invocation can never exceed a
pre-signed policy, never negotiate scope interactively, and fails closed on any
ambiguity. An agent "inheriting excessive trust" is structurally prevented — it
gets *less* authority than a human, never more. Note the CIDR asymmetry: a
**human** may supply an explicit, capped CIDR (never implicit, never auto-
expanded — §3.3 still applies), while an **agent** is restricted to exact hosts
always.

### 3.3 Prohibited in v1.0 (explicit deny-list)

The following are **not implemented** and must be refused if somehow requested:
ARP sweeping · DNS-zone enumeration · mDNS/SSDP harvesting · subnet inference
from local interfaces · automatic `/24` (or any) CIDR expansion · credentialed
probing · banner brute-forcing. Every host and port is supplied explicitly in
the manifest. Discovery is enumeration of *authorized* targets, never *discovery
of new* targets.

### 3.4 Immutable operational budgets

Compile-time **ceilings** that flags may lower but never raise:

| Budget | Purpose |
|---|---|
| max hosts / run | bounds blast radius |
| max ports / host | no port sweeps |
| max concurrency | no network flooding |
| max total connections / packets | hard traffic cap |
| max wall-clock runtime | bounded engagement |
| per-target cooldown | non-aggressive pacing |
| **global abort switch** | one signal (SIGINT / a sentinel file) halts everything immediately |

Rationale the operator flagged: AI-assisted operations compress recon timelines,
so the safety rails must be *structural ceilings*, not advisory defaults. `agent`
invocation gets stricter ceilings than `human` (§3.2).

### 3.5 Hostile-by-default remote response handling

Every byte a remote host returns is untrusted adversarial input. MCP-specific
research flags prompt injection, tool poisoning, capability misrepresentation,
and implicit trust propagation — so:

- Remote banners, errors, tool descriptions, and MCP metadata are **never**
  placed raw into a report, a log, or (especially) any LLM/agent context.
- Anything surfaced is first **normalized and sanitized**: length-capped,
  control-characters and ANSI stripped, non-UTF-8 rejected, and clearly labelled
  as *untrusted remote data* — never interpolated into remediation prose or a
  prompt. This extends the tool's existing "no raw secret reaches output"
  discipline to "no raw remote bytes reach output."
- Exposure-only detection means we read the **minimum** needed to answer "is an
  MCP server listening here?" — we do not enumerate tools or pull descriptions in
  v1.0.

### 3.6 CLI surface (illustrative)

```
mcpscan lan \
  --manifest ./auth/eng-2026-0710.toml \
  --allowed-signers ./auth/allowed_signers \
  --invoker human \
  --dry-run                # print the verified target/port plan; send nothing
```

Refusals are specific: `refusing 8.8.8.8: public address requires an enterprise
policy file (--enterprise-policy), not a flag`.

### 3.7 Report & audit trail

All renderers stamp: the manifest hash + `authorization_id`, the invoker mode,
the resolved target/port plan, per-host reachability + MCP-detection outcome, and
a machine-readable `lan_scan` block (JSON/SARIF). No remote secret can appear —
we never read one.

## 4. Threat-model additions (§8 deltas)

| Risk | Mitigation |
|---|---|
| Scanning third parties | Exact-target-only + signed manifest + private default + public hard-denial + recorded attestation. High-friction, logged, operator-owned. |
| Autonomous over-reach | `--invoker agent` = signed policy only, tighter budgets, fail-closed on ambiguity, never interactive. |
| Broad sweep / flooding | No expansion (§3.3) + immutable ceilings (§3.4) + global abort. |
| Malicious remote response | Hostile-by-default sanitization (§3.5); nothing raw reaches report/LLM. |
| "Security tool as weapon" optics | Inert without a signed manifest; separate subcommand; dedicated `docs/LAN_SCANNING.md` operator page states the legal/ethical boundary. |

## 5. Testing

- **No real network in the suite** — the probe transport is injected (as
  `enumerate_listening` already is). Tests drive reachable/unreachable/looks-like-
  mcp/timeout and assert every refusal path.
- Manifest tests: bad signature → refuse; expired → refuse; target/port not in
  manifest → refuse; public target without enterprise policy → refuse.
- Invoker tests: `agent` + ambiguity → non-interactive denial; `agent` budgets
  strictly tighter than `human`.
- Budget tests: ceilings cannot be raised past the compiled cap; abort halts.
- Sanitization tests: injected hostile banner (ANSI, control chars, prompt-
  injection string) is neutralized and labelled, never emitted raw.
- Golden audit-record test (deterministic given a fixed manifest + clock).

## 6. Phasing

1. **Phase A** — `mcpscan lan` subcommand: manifest verify (`ssh` scheme) +
   hashed audit record, `--invoker` split, exact-target exposure probe, immutable
   budgets, hostile-response sanitization, `--dry-run`, exposure-only findings,
   operator docs.
2. **Phase B** — the `[crypto]` extra (`ed25519` manifest scheme), explicit
   budget-capped CIDR for `human` invocations, enterprise-policy file (public-
   target enablement, org-wide ceilings), `lan_scan` SARIF block polish.

Both signature schemes and both scope modes (exact / human-CIDR) are in v1.0;
Phase A ships the dependency-free defaults, Phase B adds the opt-in paths.

## 7. Approved v1.0 decision (recorded)

Build `mcpscan lan` as its own module with: exact-target-only scope · private-
address default · public hard-denial unless enterprise policy · signed
authorization manifest + hashed audit record · human-vs-agent invocation
controls · strict immutable probing budgets · sanitized response processing ·
exposure-only findings · **no automatic remediation or follow-on scanning.**

## 8. Positioning

`mcpscan lan` is the first network-facing module of what the operator frames as
an **AI Infrastructure Security Platform** — assessment-oriented, read-only,
discovery-never-authority. The long-term shape (discovery → posture → attack-path
→ trust → drift → dashboards → advisor) is captured in
[`VISION.md`](./VISION.md); this proposal deliberately ships only the safe,
exposure-only foundation.

## 9. Sub-decisions — resolved (both, not either/or)

Operator decision 2026-07-10: **support both options in each case**, layered so
the default install stays stdlib-only and the heavier paths are strictly opt-in.

1. **Signature mechanism — both.** `ssh` scheme (`ssh-keygen -Y verify`) is the
   dependency-free default (Phase A); `ed25519` via a vetted library is available
   through the `[crypto]` extra (Phase B). The manifest declares its scheme; an
   `ed25519` manifest without the extra is refused, never downgraded.
2. **Scope — both, invoker-gated.** `--invoker human` may use exact IPs **or** an
   explicit, budget-capped `/30`–`/24` (with confirmation; never implicit, never
   auto-expanded). `--invoker agent` is **exact-IP/`/32` only, always.** Exact-
   only ships in Phase A; human-CIDR in Phase B.

No open questions remain. **Phase A is ready to build** on your go-ahead.
