# Proposal — Integrating the Agent Trust Broker (ATB) with mcpscan

**Status:** **Accepted** — the recommendation (Option 2 + Option 3, bridge never
code-merge) is recorded as [ADR-17](../DECISIONS.md), and the assessment check it
calls for is specified in [ATB_POSTURE_CHECK.md](ATB_POSTURE_CHECK.md). This note
stands as the options analysis behind that decision. Relates to
[VISION.md](VISION.md) (governance tier) and ADR-1/8/9 (assessment-only identity).

> **Governing tension (the whole point of this note):** mcpscan is
> **assessment-only** — *discovery never converts into authority* (LAN proposal),
> zero-egress, stateless, never writes (ADR-5/8/9/13). The ATB is the opposite: an
> **active runtime reference monitor** that *is* authority — it grants, denies, and
> holds agent actions. These two products can be **neighbours and partners, but
> they must not become one thing**, or mcpscan loses the guarantee that is its
> entire trust proposition.

---

## 1. Context — what actually exists today

Three states were found on disk, which is why "two repos" felt tangled:

| # | Location | Git remote | What it really is | Maturity |
|---|----------|-----------|-------------------|----------|
| A | `~/agent-trust-broker` | `IRsoctierDT/agent-trust-broker` | **The real ATB** — `ianua_atb`: identity, policy, hash-chained audit, escalation, operator CLI | Milestones 1–2, stdlib-only, unreleased |
| B | `~/Desktop/IANUA-Broker` | `IRsoctierDT/IANUA-Broker` | **This scanner** — `ai-agentic-mcpscan` | Released **v1.4.0** |
| C | `~/Desktop/IANUA-Broker/agent-trust-broker/` | *(untracked)* | **Stale Day-01 scaffold** of the ATB (no `atb/` package); not committed to anything | Dead cruft |

**Step zero (reversible, non-controversial):** delete state **C**. It is untracked
local cruft superseded by **A**, and it is the sole reason it looked like two ATBs
exist. Removing it changes nothing tracked.

---

## 2. The core tension — assessment vs. authority

mcpscan's identity is a set of hard guarantees a security buyer relies on:

- **Assessment-only / read-only** (ADR-5): never writes to user systems.
- **Discovery never converts into authority** (LAN proposal governing principle).
- **Offline / zero-egress by default** (ADR-9), **stateless** (ADR-13).

The ATB, by construction (ATB-01/03), **is** authority: it mints identities, makes
allow/deny/escalate decisions, holds actions at a human gate, and keeps a durable
hash-chained audit. It is stateful and inline on the live action path.

Folding the ATB *into* the mcpscan package would import an active-authority, stateful,
inline component into a tool whose whole value is that it has none of those
properties. That breaks the contract. **So the question is not "merge or bridge" in
the abstract — it is "how do we partner them without contaminating mcpscan's
assessment-only guarantee."**

---

## 3. Options considered

### Option 1 — Monorepo merge (one repo, two packages)
Bring **A** into **B** via `git subtree` (history preserved) as a second top-level
package alongside `src/mcpscan`; each keeps its own build, tests, and release.

- **Pros:** one clone / one CI for the whole MCP Sentinel suite; atomic cross-cutting
  edits; simplest day-to-day for a solo builder.
- **Cons:** invites accidental coupling; a reader sees an "authority" package living
  inside an "assessment-only" product and reasonably doubts the guarantee; two release
  trains (`ai-agentic-mcpscan` vs `ianua-atb`) in one repo is awkward with release-please;
  ATB loses standing as an independently-consumable EAODS reference implementation.

### Option 2 — Bridge, two repos (recommended)
Keep **A** and **B** separate. The ATB stays its own runtime component and publishable
artifact. mcpscan integrates only in ways that respect its guardrail (see §4).

- **Pros:** each product keeps its own guarantee, CI, and release cadence; ATB remains a
  reusable reference implementation; clean ownership boundary; the integration surface is
  small and explicit.
- **Cons:** two repos to track; cross-cutting changes span two PRs; requires a pinned
  dependency / version discipline.

### Option 3 — Feature bridge only (no structural change)
Leave both repos as-is; mcpscan gains an **assessment** capability that evaluates ATB
deployments (read-only): *is this MCP setup fronted by a trust broker? is the policy
sound / least-privilege / fail-closed?*

- **Pros:** lightest touch; perfectly on-guardrail (pure assessment); directly serves the
  VISION governance tier.
- **Cons:** it is an integration *of findings*, not of runtime — it does not by itself let
  the ATB protect live traffic. It is a complement to Option 2, not a substitute.

---

## 4. Recommendation — Option 2 + Option 3 (bridge, then assess), never Option 1's code-merge

Keep the ATB as a **separate runtime component** (its own repo/package), and let mcpscan
relate to it in exactly one on-guardrail way: **assessment**.

Concretely, two non-overlapping integration surfaces:

1. **mcpscan → ATB (assessment, read-only).** A new scanner capability (a VISION
   governance-tier check) inspects a target for the presence and posture of an ATB:
   is privileged tool access fronted by a broker? are policies fail-closed, least-privilege,
   escalation-preserving? It emits findings/SARIF like every other check. This *stays
   assessment-only* — it reads and grades; it never enforces. Fits ADR-5/8/9.
2. **ATB → runtime (enforcement, separate).** The ATB-03 PEP wraps the live MCP transport
   in the *runtime* (not in mcpscan). This is where "wiring" actually happens: agents call
   through the PEP, which consults the ATB policy engine. mcpscan never sits on this path.

This gives you the honest story: **mcpscan tells you that you need runtime enforcement and
grades whether you have it; the ATB provides that enforcement.** Two products, one mission,
no contaminated guarantee.

Co-location (Option 1) is acceptable *only* if you later want a single "IANUA suite" repo
**and** you keep the packages independently guaranteed and released — but the code and the
trust contracts stay separate regardless. Merging the *contracts* is the one thing to never do.

---

## 5. What the bridge looks like concretely

```
        ┌─────────────── assessment plane (mcpscan, read-only) ───────────────┐
        │  mcpscan scan  ──▶  ATB-posture check  ──▶  finding + grade + SARIF   │
        └──────────────────────────────────────────────────────────────────────┘
                                     (reads config; never acts)

        ┌─────────────── runtime plane (ATB, authority) ─────────────────────┐
   agent │  tool call ─▶ ATB-03 PEP ─▶ PolicyEngine.authorize ─▶ allow/deny/    │
         │                              escalate ─▶ hash-chained audit          │
        └──────────────────────────────────────────────────────────────────────┘
                                     (acts; on the live path)
```

- Dependency direction: if anything, **mcpscan may depend on `ianua-atb` types** (read-only,
  to recognise/parse an ATB deployment). The ATB must **never** depend on mcpscan.
- Versioning: pin `ianua-atb` in mcpscan by exact version; bump deliberately.
- Guardrail test: the ATB-posture check must pass mcpscan's existing default-run isolation
  test (NFR-SEC1) — zero egress, no writes — like every other check.

---

## 6. Consequences

- mcpscan keeps its assessment-only guarantee intact and gains a marquee governance check
  that differentiates it (VISION Tier: "assesses governance").
- The ATB remains an independently releasable EAODS reference implementation (PAT-0001).
- The stale nested copy (state C) is removed; no more ambiguity about "which ATB."
- Two release trains remain; that is a feature (independent blast radius), not a bug.

---

## 7. First reversible steps (only after operator approval)

1. Delete the untracked stale scaffold at `~/Desktop/IANUA-Broker/agent-trust-broker/`.
2. Record the accepted topology as **ADR-17** in `docs/DECISIONS.md` once chosen.
3. Open a follow-up proposal for the **ATB-posture check** (scope, findings, grades) under
   the VISION governance tier.
4. (Separately, in the ATB repo) proceed with ATB-03 Milestone 3 — the PEP — as the runtime
   enforcement arm.

Nothing above is done yet; this note is the map only.

---

## 8. Open decisions for the operator

- **Repo topology:** two repos (recommended) vs. one "IANUA suite" monorepo with independent
  packages. Either preserves the recommendation; it is an organizational choice.
- **Dependency:** may mcpscan take a read-only dependency on `ianua-atb` types, or should the
  ATB-posture check parse a documented on-disk shape instead (zero dependency)?
- **Naming:** the folder `~/Desktop/IANUA-Broker` maps to remote `IANUA-Broker` but the package
  is `ai-agentic-mcpscan`. Decide whether the product name is IANUA-Broker or mcpscan, and
  align repo/remote/package before more branding accretes.
