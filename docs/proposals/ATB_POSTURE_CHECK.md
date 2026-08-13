# Proposal — the ATB-posture check (governance tier, assessment-only)

**Status:** **Design, for review** · defines the on-disk **contract** the check
reads and the findings it emits · **no check code lands until the ATB pins that
contract** · Relates to [ADR-17](../DECISIONS.md) (bridge, never code-merge),
[ATB_INTEGRATION.md](ATB_INTEGRATION.md), and [VISION.md](VISION.md) (governance
tier).

> **One sentence:** mcpscan should be able to look at a deployment and grade
> whether privileged agent-tool access is fronted by a broker, and whether that
> broker is **fail-closed** and **least-privilege** — reading only, never
> enforcing. This note pins *what a brokered deployment looks like on disk* so
> the check is a small, non-speculative follow-up rather than a guess at an
> interface that does not exist yet.

---

## 1. Why this is a proposal and not yet code

Per [ADR-17](../DECISIONS.md), mcpscan relates to the Agent Trust Broker (ATB)
in exactly one on-guardrail way: **assessment**. The check must read a
**documented on-disk shape** (preferred — zero dependency on the ATB package)
to recognise a brokered deployment. The ATB is at its **Day-1 v0.1 baseline**
(per its own `DESIGN.md`): the interception architecture, policy engine, HITL
gate, signed tool manifests, and audit log are *designed* but the on-disk
artifacts are not yet emitted — the `agents/policies/` and `mcp/` packages are
still stubs. So building the check now would hard-code a guessed interface.
Instead, this note *defines* the contract in the ATB's own vocabulary; the ATB
implements to it; the check then follows in a few hundred lines that reuse the
existing check/adapter seams.

**mcpscan owns the assessment contract; the ATB conforms to it.** That ordering
keeps the dependency direction correct (ADR-17): mcpscan never depends on ATB
runtime code.

## 2. The on-disk contract (grounded in the ATB's design)

The ATB's `DESIGN.md` fixes the model this check assesses: a **bidirectional
inline trust gate** with one policy engine, an **architectural (non-
configurable) human-in-the-loop escalation gate**, an **allowlist + signed tool
manifests** (boundary B2), and a **tamper-evident audit log** (B6). A deployment
is **brokered** when the ATB writes a broker manifest naming the MCP servers it
fronts. Proposed shape — a single file `~/.config/ianua/broker.json` (POSIX) /
`%APPDATA%\ianua\broker.json` (Windows), read via `io_safe` like every surface:

```json
{
  "schema_version": "1.0",
  "fronts": ["~/.mcp.json#shell", "~/.mcp.json#db"],  // server ids it mediates
  "allowlist": "least_privilege",   // "least_privilege" | "wildcard"
  "tool_manifests": "signed",       // "signed" | "unverified"  (B2 / threat T2)
  "audit_log": "enabled"            // "enabled" | "off"        (B6 / threat T6)
}
```

The server ids in `fronts` are exactly the `location#name` subjects the trust
engine already uses, so the check joins the manifest to discovered servers with
no new discovery. Note there is **no `mode`/`escalation` field**: the ATB's HITL
gate is *architectural, not configurable* (`DESIGN.md` §2.3), so a genuine ATB
deployment cannot be "fail-open" by construction — the check's job is to confirm
the broker is **present** in front of privileged tools and that its two
*configurable* postures (allowlist scope, manifest signing) and its audit trail
are sound. Only these non-secret fields are read; the file is hostile input
(malformed → a degraded finding, never a crash); nothing is written.

Alternative, dependency-free-er signal (either/both may be supported): a server
whose `command` routes through the ATB **interception point** (a documented
wrapper executable) is mediated at the transport, so its privileged tools run
behind the broker even without a manifest entry. The check recognises that
command shape too.

## 3. Findings (governance dimension)

Each maps to a control/threat in the ATB's own threat model (`DESIGN.md` §5):

| id | when | severity | ATB threat |
|---|---|---|---|
| `BROKER-ABSENT` | a server holds **privileged** tool grants (the existing dangerous/wildcard `TOOL_PRIVILEGE` predicate) but is **not** fronted by any broker manifest nor behind the interception wrapper | **High** — privileged agent action with no reference monitor | T3, T5 |
| `BROKER-MANIFEST-UNVERIFIED` | a broker fronts privileged servers but `tool_manifests == "unverified"` — tool metadata is not signature-checked | **High** — reopens tool-description poisoning | T2 |
| `BROKER-NO-AUDIT` | `audit_log == "off"` — consequential actions leave no oversight trail | **Medium** | T6 |
| `BROKER-ALLOWLIST-PERMISSIVE` | `allowlist == "wildcard"` — brokered, but not least-privilege | **Medium** | T3 |
| `BROKER-PARSE-ERROR` | the manifest is present but malformed | **Low** (`inspection_incomplete`, like other degraded reads) | — |

A deployment where every privileged server is fronted, with a least-privilege
allowlist, signed tool manifests, and the audit log enabled, emits **no**
governance finding — the positive case grades clean, which is the point of a
governance tier.

These reuse the scanner's own `TOOL_PRIVILEGE` predicate for "privileged", so
the governance view never diverges from what `scan`/`trust` already flag.

## 4. Where it lives (open design decisions)

- **Dimension.** A new `Dimension.GOVERNANCE` is the honest home, but adding an
  enum member changes the scan-JSON `dimension_grades` shape (a coordinated
  `SCHEMA_VERSION` bump, per the wave schema-coordination discipline). The
  cheaper alternative is to ride `Dimension.TOOL_SCOPE` (tool-agency is a
  tool-scope concern). **Recommendation:** a new `GOVERNANCE` dimension in a
  deliberate minor with the bump, since governance scoring is a marquee
  differentiator worth its own axis.
- **Surface.** Most natural as a governance check family that runs inside `scan`
  when a broker manifest exists (always emitting `BROKER-ABSENT` for privileged-
  but-unbrokered servers), and is surfaced by `atlas` (mapped to NIST AI RMF
  GOVERN and CIS control families) and factored into `trust`. No new top-level
  command needed.
- **Atlas mapping.** Every new finding id needs a `MAPPINGS` row (the
  completeness test enforces it): `BROKER-*` → NIST AI RMF **GOVERN**, CIS
  Controls **6** (access control), OWASP LLM **LLM08** (excessive agency).

## 5. Guardrail (non-negotiable)

- **Assessment-only.** The check reads the manifest and grades; it never writes,
  never enforces, never contacts the ATB at runtime.
- **Offline / zero egress.** No network. It must pass the default-run isolation
  test (NFR-SEC1) like every other check.
- **Secretless.** The manifest carries no secrets; if a future field ever did,
  it is fingerprinted at read like everything else.
- **Fail-safe.** A missing manifest is the common case (unbrokered) and is not
  an error; a malformed one degrades to a finding, never a crash.

## 6. Sequencing

1. **Now:** this proposal + [ADR-17](../DECISIONS.md) recorded. *(done)*
2. **ATB side:** the ATB (repo `agent-trust-broker`) writes the `broker.json`
   manifest in §2's shape when it fronts a deployment, and/or ships the named
   PEP wrapper command. This is the blocking dependency.
3. **mcpscan side (follow-up PR):** `checks/governance.py` + a broker-manifest
   adapter surface + the findings in §3, behind the guardrail in §5, with the
   dimension/atlas decisions from §4. Estimated small — it reuses the trust
   `TOOL_PRIVILEGE` predicate, the `io_safe` reader, and the adapter/atlas seams.

Nothing in step 3 lands until step 2 pins the contract; this note is the map.
