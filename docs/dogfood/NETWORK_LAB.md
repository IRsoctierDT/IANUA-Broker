# Network-lab runbook (T-402, Phase 3 — the socket + `lan` surface)

This is the operator runbook for the **network ground-truth** pass: validating
mcpscan's exposure classifier and `mcpscan lan` against what a network *actually*
exposes, using pfSense + Suricata as the independent oracle (proposal §2.2, §5).

You run this on your lab; I can't reach it. Everything here is concrete — exact
binds, exact manifests, exact expected findings — so the run is a checklist, not
a design exercise. The measurable bar (proposal §5): **the exposure classifier
must agree with the pfSense/Suricata ground truth on 100 % of the lab binds.**

---

## 0. Topology

Addresses below are **documentation placeholders**, not a real network:
`198.51.100.0/24` is TEST-NET-2 from
[RFC 5737](https://www.rfc-editor.org/rfc/rfc5737), reserved for examples.
Substitute your own lab's addresses when you run this.

They are not arbitrary, though. Python's `ipaddress` reports TEST-NET as
private (IANA marks it not globally reachable), so `classify_reachability()`
returns `private_lan`/HIGH for these exactly as it does for an RFC 1918
address, and `mcpscan lan`'s private-target gate accepts them. Every expected
finding in this runbook therefore holds verbatim with these placeholders, and
holds equally once you substitute your own RFC 1918 addresses.

```
        ┌────────────────────────┐         ┌──────────────────────┐
        │  lab host (target)     │         │  operator host       │
        │  198.51.100.20         │         │  198.51.100.10       │
        │                        │         │                      │
        │  mcp-loopback :8801 ───┼─ lo     │  mcpscan lan ───────▶│ probes .20
        │  mcp-wildcard :8802 ───┼─ 0.0.0.0│                      │
        │  mcp-lan-iface:8803 ───┼─ .20    │                      │
        └───────────┬────────────┘         └──────────────────────┘
                    │ span/tap
             ┌──────▼───────┐
             │ pfSense +    │  Suricata sees which binds are reachable
             │ Suricata     │  off-host  →  the ground truth
             └──────────────┘
```

Use the synthetic listeners in
[`lab/synthetic/docker-compose.yml`](../../lab/synthetic/docker-compose.yml) for
the three bind classes, or real MCP servers configured the same way.

---

## 1. Stand up the target binds

```bash
# On the lab host (198.51.100.20):
HOST_LAN_IP=198.51.100.20 docker compose -f lab/synthetic/docker-compose.yml up -d
ss -tlnp | grep -E ':(8801|8802|8803)'   # confirm the three binds
```

Ground-truth expectation (what the network *should* show):

| Bind | Address | Reachable off-host? | mcpscan must classify |
|---|---|---|---|
| `:8801` | `127.0.0.1` | **No** (loopback) | no exposure finding |
| `:8802` | `0.0.0.0` | **Yes** (wildcard) | `EXPOSE-BIND` (CRITICAL) |
| `:8803` | `198.51.100.20` | **Yes** (LAN iface) | `EXPOSE-BIND` (CRITICAL) |

## 2. Confirm the ground truth with Suricata/pfSense

From the **operator host** (198.51.100.10), touch each port and read the oracle,
don't trust the target's self-report:

```bash
for p in 8801 8802 8803; do nc -z -w2 198.51.100.20 $p && echo "$p OPEN" || echo "$p closed"; done
```

Expected from off-host: `8801 closed`, `8802 OPEN`, `8803 OPEN`. Cross-check the
Suricata event log (`/var/log/suricata/eve.json`) / pfSense state table for
flows to `.20:8802` and `.20:8803` and none to `.20:8801`. **This is the oracle**
— if it disagrees with the table in §1, fix the lab before judging the tool.

## 3. Validate the local exposure classifier (`scan`)

On the **lab host**, run a normal scan and check its socket-exposure findings
against §1:

```bash
mcpscan scan --json scan.json
python - <<'PY'
import json
exp = {b["bind_addr"]: b for b in json.load(open("scan.json"))["servers"] if b.get("bind_addr")}
# 8802 and 8803 must carry EXPOSE-BIND; 8801 must not appear as exposed.
PY
```

Pass = mcpscan flags `:8802` and `:8803` as exposed and is silent on `:8801`,
matching the oracle. Any disagreement is a classifier-tuning bug — write it up
with the [triage template](TRIAGE_TEMPLATE.md) (`surface: socket`).

## 4. Validate `mcpscan lan` against the same targets

`lan` is exposure-only and **inert without a signed manifest**. Author one that
authorizes exactly the lab target, sign it, and run from the operator host.

**`auth.toml`** (exact host, the lab's two service ports):

```toml
authorization_id = "DOGFOOD-LAB-2026"
operator         = "you@example.com"
expires_at       = "2026-12-31T23:59:59Z"
targets          = ["198.51.100.20/32"]   # exact /32 — the lab host only
ports            = [8802, 8803]            # the two exposed binds
```

Sign and dry-run first (verifies the manifest, sends **no packets**):

```bash
ssh-keygen -Y sign -n mcpscan-lan -f ~/.ssh/id_ed25519 auth.toml   # -> auth.toml.sig
printf 'you@example.com namespaces="mcpscan-lan" %s\n' "$(cat ~/.ssh/id_ed25519.pub)" > allowed_signers

mcpscan lan --manifest auth.toml --signature auth.toml.sig \
            --allowed-signers allowed_signers --invoker human --dry-run
```

Then the real run, capturing both machine formats:

```bash
mcpscan lan --manifest auth.toml --signature auth.toml.sig \
            --allowed-signers allowed_signers --invoker human \
            --json lan.json --sarif lan.sarif
```

Expected:

- **Terminal / `lan.json`:** a `LAN-EXPOSED` (HIGH) finding for
  `198.51.100.20:8802` and `198.51.100.20:8803`.
- **`lan.sarif`:** each finding as a SARIF **logical location** —
  `kind: resource`, `fullyQualifiedName: lan://198.51.100.20:8802` (ADR-16),
  with **no** `physicalLocation` and no synthetic filename. Validate with any
  SARIF tool; do **not** expect GitHub code scanning to annotate it (it needs a
  file — that's by design).
- **Audit record** (`lan.json.audit`): the authorization id, operator, manifest
  sha256, and a results digest — the tamper-evident record of an authorized run.

### Negative controls (the safety properties — these must *refuse*)

Run each; every one must **refuse and send no packet**:

```bash
# 1. Expired manifest -> refused at the expiry gate.
sed 's/2026-12-31/2020-01-01/' auth.toml > expired.toml   # re-sign, then run -> refused

# 2. Public target without an enterprise policy -> refused at the scope gate.
sed 's#198.51.100.20/32#8.8.8.8/32#' auth.toml > public.toml   # re-sign, run -> refused

# 3. Wrong/absent signature -> refused at the signature gate (no probe).
mcpscan lan --manifest auth.toml --signature /dev/null \
            --allowed-signers allowed_signers --invoker human    # -> refused

# 4. --invoker agent + a CIDR range -> refused (agent gets exact-hosts-only).
sed 's#198.51.100.20/32#198.51.100.0/30#' auth.toml > range.toml  # re-sign
mcpscan lan --manifest range.toml … --invoker agent               # -> refused
```

A refusal here is a **pass**: it proves *discovery never converts into
authority*. A probe that proceeds despite any of these is a release blocker.

## 5. Record the result

For each lab bind, record `oracle` vs `mcpscan` and mark agreement. The pass bar
is **100 % agreement** on the enumerable bind set (§5 of the proposal). File any
disagreement with the [triage template](TRIAGE_TEMPLATE.md), minimize it to a
socket fixture, and add it to the regression suite. Tear the lab down when done:

```bash
docker compose -f lab/synthetic/docker-compose.yml down
```
