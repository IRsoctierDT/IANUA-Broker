# `mcpscan lan` — operator guide

`mcpscan lan` assesses MCP **exposure** on hosts you are **authorized to test**.
It is a separate, gated command from `mcpscan scan` (which is localhost-only) and
is **inert without a signed authorization manifest**.

> **Legal/ethical boundary.** Only run `mcpscan lan` against hosts you own or have
> explicit, documented authorization to test. The signed manifest is your
> recorded assertion of that authorization. Scanning third-party systems without
> authorization may be illegal. **Discovery never converts into authority:** the
> tool confirms whether an MCP server is reachable and does nothing else — no auth
> attempts, no payloads, no remote config reads, no exploitation.

## 1. What it does (and doesn't)

- **Does:** TCP-connects to the exact `host:port` pairs named in a signed
  manifest and sends a single bare MCP handshake to answer *"is an MCP server
  listening here?"* Reachable MCP endpoints become HIGH `LAN-EXPOSED` findings.
- **Doesn't:** read remote configs, enumerate tools, pull descriptions, try
  credentials, sweep ports, or expand scope. It is exposure-only.
- **Private by default:** public (routable) targets are refused unless an
  enterprise policy explicitly names them (§5).
- **Bounded:** immutable per-invoker budgets cap hosts, ports, concurrency, total
  connections, runtime, and pacing; `agent` invocations are strictly tighter.

## 2. Write a manifest

A manifest is a TOML file naming the exact authorized targets, ports, operator,
and expiry:

```toml
authorization_id = "ENG-2026-0710"      # your ticket / engagement id
operator         = "you@example.com"    # must match the signing identity
expires_at       = "2026-07-10T23:59:59Z"  # after this, runs are refused
targets          = ["198.51.100.20/32"] # exact hosts / /32 (a human may use a capped CIDR)
ports            = [3000, 8000]         # explicit; no default port sweep
```

`--invoker agent` may use **exact hosts only** (no CIDR). `--invoker human` may
add an explicit, budget-capped CIDR (e.g. `198.51.100.0/28`). Ranges are never
implicitly expanded.

## 3. Sign it (default: SSH)

The manifest must carry a detached signature. The default scheme reuses your
existing SSH key — no extra dependency:

```bash
# one-time: an allowed-signers file mapping the operator identity to its public key
printf '%s %s\n' "you@example.com" "$(cat ~/.ssh/id_ed25519.pub)" > allowed_signers

# sign the manifest (namespace MUST be mcpscan-lan)
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n mcpscan-lan auth.toml
# -> writes auth.toml.sig
```

(The `ed25519` scheme via the `[crypto]` extra is a separate, opt-in path.)

## 4. Run

```bash
# Dry run first: verify the manifest and print the plan without sending a packet.
mcpscan lan --manifest auth.toml --signature auth.toml.sig \
            --allowed-signers allowed_signers --invoker human --dry-run

# Real run: probe the authorized targets.
mcpscan lan --manifest auth.toml --signature auth.toml.sig \
            --allowed-signers allowed_signers --invoker human \
            --json lan-report.json
```

Every run prints an **audit stamp** (authorization id, operator, manifest
SHA-256) and can write a combined `{audit, report}` JSON.

## 5. Public targets (enterprise policy)

Public addresses are a **hard denial** by default. To authorize specific public
targets, supply an enterprise policy file — a flag alone is never enough:

```toml
# policy.toml
public_targets = ["203.0.113.0/28"]   # exactly what the org has authorized
```

```bash
mcpscan lan --manifest auth.toml --signature auth.toml.sig \
            --allowed-signers allowed_signers --invoker human \
            --enterprise-policy policy.toml
```

A public target is permitted only when it is a subnet of a `public_targets`
entry; anything else is still refused.

## 6. Reading refusals

Refusals are deliberate and specific. Common ones:

| Message | Meaning |
|---|---|
| `invalid manifest: …` | The TOML is malformed or a field is invalid. |
| `manifest expired at …` | `expires_at` has passed — re-issue and re-sign. |
| `signature rejected: …` / `ssh-keygen not found` | The signature didn't verify (wrong key/namespace/identity) or OpenSSH isn't installed. |
| `refusing non-private target …` | A public target without a covering enterprise policy. |
| `agent invocation may not use CIDR …` | An `agent` run supplied a range; use exact hosts. |
| `… exceeds the host / per-host / connection budget …` | The plan is larger than the immutable budget allows. |

A refusal means **no packet was sent**.

## 7. Exit codes

Same as `scan`: non-zero when a finding meets `--fail-on` (default `high`), so a
`LAN-EXPOSED` finding fails CI by default. Refusals and usage errors exit `2`.

---

Full design, threat model, and roadmap:
[`docs/proposals/LAN_SCANNING.md`](proposals/LAN_SCANNING.md).
