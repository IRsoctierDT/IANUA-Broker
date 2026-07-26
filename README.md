# IANUA-Broker 

> Local-first, **offline-by-default** security posture scanner for MCP /
> local-agent setups. Find exposed servers, plaintext secrets, over-broad tool
> scopes, and unpinned packages — then fix the highest-impact issues first.

**Status:** Stable (`v1.x`) — safe to run (read-only, offline by default), with
a stable CLI surface, JSON schema, and check ids covered by semver. CLI
command: `mcpscan`. License: Apache-2.0.

## What it does (MVP)

- **Discovers** MCP servers on the local machine via socket/process enumeration
  (directly catching `0.0.0.0` / non-loopback exposure) plus a loopback probe of
  `/mcp` and `/sse`.
- **Statically audits** Claude-ecosystem (`.claude/settings.json`, `.mcp.json`,
  `claude_desktop_config.json`), **Cursor** (`~/.cursor/mcp.json`,
  `.cursor/mcp.json`), **Windsurf** (`~/.codeium/windsurf/mcp_config.json`),
  **Cline** (VS Code `globalStorage/…/cline_mcp_settings.json`), **VS Code**
  (`.vscode/mcp.json`, user `mcp.json`), **Zed** (`.zed/settings.json`, user
  `~/.config/zed/settings.json`), and **Continue** (`~/.continue/config.yaml`,
  `.continue/config.yaml` — needs the `[yaml]` extra) agent configs — plus
  `.env` — for plaintext secrets, auto-approval flags, over-broad tool scopes,
  and unpinned versions.
- **Scores** each server **A–F** across four dimensions (exposure, credential
  hygiene, tool-scope breadth, version pinning).
- **Reports** a prioritized, **redacted**, advise-only remediation in four
  forms: terminal, a self-contained HTML file, stable JSON, and SARIF 2.1.0 for
  GitHub code scanning.
- **Inventories** (`mcpscan inventory`) the machine's AI infrastructure as a
  classified, typed asset list — agent hosts, MCP servers, model servers,
  inference endpoints, LLM gateways, vector DBs — with per-asset evidence and
  confidence.

## Trust properties (by design)

- **Localhost only** — never touches the LAN or third-party systems.
- **Offline + zero telemetry by default** — `--online` opt-in adds OSV/PyPI
  enrichment and says so.
- **Secrets never leak** — redacted everywhere; `--show-secrets` reveals only a
  masked/partial value, with a warning.
- **Advise-only by default** — never writes to your config files unless you pass
  `--fix`, which applies only safe, reversible tool-scope edits and backs up
  every file it touches first.
- **Fully stateless** — writes only the report you explicitly ask for.
- **Passes its own scan** — exposes no port, ships no plaintext secret.

## Install

```bash
pipx install ai-agentic-mcpscan            # provides the `mcpscan` command
pipx install "ai-agentic-mcpscan[yaml]"    # + audit Continue's config.yaml
pipx install "ai-agentic-mcpscan[crypto]"  # + verify ed25519 LAN manifests
```

The base install is stdlib-only (plus `psutil`). The optional `[yaml]` and
`[crypto]` extras enable Continue config auditing and library-based Ed25519
manifest verification, respectively.

Or from source:

```bash
git clone https://github.com/IRsoctierDT/IANUA-Broker.git
cd IANUA-Broker && pipx install .
```

Requires **Python 3.11+** (macOS, Linux, Windows).

## Usage

```bash
mcpscan scan                          # scan localhost + cwd project configs
mcpscan scan --root ~/project         # scan a specific project root (repeatable)
mcpscan scan --json report.json       # also write a stable JSON report (0600)
mcpscan scan --html report.html       # also write a self-contained HTML report
mcpscan scan --sarif results.sarif    # also write SARIF 2.1.0 for code scanning
mcpscan scan --fail-on critical       # CI: exit non-zero only on Critical
mcpscan scan --online                 # opt-in OSV enrichment (discloses egress)
mcpscan scan --show-secrets           # reveal masked (first-2/last-2) values
mcpscan scan --absolute-paths         # show full paths instead of ~
mcpscan scan --fix                    # apply safe tool-scope fixes (backs up first)
mcpscan inventory                     # classified AI/MCP asset list (see below)
mcpscan atlas                         # findings mapped to security frameworks
mcpscan atlas --matrix                # the full check-id -> framework matrix
mcpscan trust                         # per-agent Trust Score + risk relationships
mcpscan trust --min-grade B           # CI: fail if any tool grades below B
mcpscan baseline --out base.json      # snapshot current posture (digest-signed)
mcpscan diff --baseline base.json     # drift vs the baseline (regressions first)
mcpscan lan  --manifest auth.toml ... # authorized network assessment (see below)
```

Exit code is non-zero when a finding meets `--fail-on` (default: `high`), so it
drops straight into CI.

### Example output

```
AI Agentic MCPscan — overall posture: F
  dimensions: credential=D, exposure=A, pinning=A, tool_scope=C
  findings: 1 critical, 1 high, 2 medium

▶ ~/.mcp.json#weather  [grade F]
  [CRITICAL] Plaintext OpenAI API key in config
             where: ~/.mcp.json
             secret: [redacted len=37 sha256:c0cc596e]
             fix:   Remove the literal value from the file. Reference it from a
                    secret manager … and rotate the exposed credential.
  [MEDIUM  ] Server 'weather' runs an unpinned package via npx
             fix:   Pin the package to an exact version (e.g. npx some-pkg@1.2.3).
```

### Fixing findings (`--fix`)

The tool is advise-only by default. `--fix` is the one explicit exception that
writes to your configs, and it stays deliberately conservative:

- **Scope:** removes over-broad **tool-scope** grants only — dangerous
  (shell/exec-class) and wildcard entries from `permissions.allow` and each
  server's `autoApprove`, using the exact predicates the scanner flags with, so
  a fixed config re-scans clean.
- **Reversible:** every modified file is copied to `<path>.mcpscan.bak` before
  the edit, and the file's permissions are preserved.
- **Nothing invented:** credential and pinning findings are **not** auto-fixed —
  a safe rewrite would need a new home for the secret or a specific version the
  tool can't know offline, so those stay manual (the report tells you what to do).

```
$ mcpscan scan --root . --fix
note: --fix modifies config files in place (backup written to <path>.mcpscan.bak) …
fixed ./.mcp.json (1 change(s); backup: ./.mcp.json.mcpscan.bak)
    removed 'Bash(*)' from permissions.allow [SCOPE-DANGEROUS-ALLOW]
applied 1 fix(es). Re-run mcpscan to confirm.
```

### AI/MCP asset inventory (`mcpscan inventory`)

Where `scan` judges posture, `inventory` answers *what AI systems exist here* —
it classifies what the scanner discovers (host configs, declared servers,
listening sockets) into a typed asset list: agent hosts, MCP servers, model
servers (Ollama, vLLM, LM Studio, llama.cpp), OpenAI-compatible inference
endpoints, LLM gateways (LiteLLM), and vector databases (Qdrant, Chroma,
Weaviate, Milvus). Three evidence tiers set the confidence: exact process name
or a product endpoint fingerprint (**high**), a generic OpenAI-compatible or
MCP transport surface (**medium**), a default-port hint alone (**low**).

```
$ mcpscan inventory
AI Agentic MCPscan — inventory: 3 asset(s)

▶ MCP servers (1)
  MCP server (HTTP transport)  [medium confidence]
    where:    127.0.0.1:40239
    process:  claude (pid 552)
    evidence: responded on /mcp (HTTP 405)

▶ Model servers (1)
  Ollama  [high confidence]
    where:    127.0.0.1:11434
    process:  ollama (pid 903)
    evidence: process name 'ollama'
…
```

Inventory **observes, never judges**: it carries no severities, always exits 0,
and `--json` gives the stable machine-readable form. Fingerprinting stays inside
the trust boundary — loopback-only bare GETs (`--no-probe` disables even that),
response bodies are treated as hostile and never reach the output. Unrecognized
services are deliberately *not* listed: a plain web server is `scan`'s exposure
concern, not an AI asset.

### Agent trust analysis (`mcpscan trust`)

Where `scan` grades hygiene, `trust` asks *what each agent tool is trusted to do
and access* — and, crucially, which **combinations** make it a lateral-movement
risk. Every MCP server gets a **Trust Score** (0–100) across four factors —
secret access, tool privilege, autonomy (auto-approval), code provenance — and
the dangerous factor *combinations* are surfaced as **risk relationships** that
no single hygiene check sees:

```
$ mcpscan trust
▶ 'db' [claude]  Trust 25/100 (grade F)
    · secret_access: holds 1 credential in its environment (+25 risk)
    · tool_privilege: auto-approves 1 dangerous tool(s) (+25 risk)
    · autonomy: auto-approves 1 tool(s) with no human in the loop (+15 risk)
    · code_provenance: runs an unpinned / remotely-fetched package (+10 risk)
    ⚠ PRIVILEGED-SECRET-HOLDER — a single compromise leaks the secrets and the
      power to use them.
    ⚠ AUTONOMOUS-PRIVILEGED — dangerous tools auto-approved, no human in the loop.
```

The relationships are the differentiator: `PRIVILEGED-SECRET-HOLDER` (secrets +
dangerous tools), `AUTONOMOUS-PRIVILEGED` (auto-approves dangerous tools),
`AUTONOMOUS-SECRET-HOLDER`, and `UNVETTED-PRIVILEGED` (unpinned code + dangerous
tools). Scoring reuses the exact predicates `scan` trusts, so the two never
diverge. `--min-grade` makes it a CI gate; `--json` emits the full analysis; a
profile is **secretless** (a credential count, never a value). Read-only and
offline.

### Drift detection (`mcpscan baseline` / `mcpscan diff`)

Turn the one-shot scan into continuous posture. `mcpscan baseline` writes a
normalized, byte-stable snapshot of the current posture (findings, server
exposure, and the AI/MCP inventory) with an integrity digest; `mcpscan diff`
compares a fresh scan against it and reports what drifted — **regressions
first**:

```
$ mcpscan diff --baseline base.json --fail-on-regression
AI Agentic MCPscan — drift: 4 change(s) (2 regression(s), 0 improvement(s))
  + [REGRESSION ] SCOPE-DANGEROUS-ALLOW — Dangerous tool auto-allowed: 'Bash(*)'
  + [REGRESSION ] PIN-UNPINNED — Server 'db' runs an unpinned package via npx
  ~ [REGRESSION ] socket://…:8000   exposure: local → exposed
```

The direction is the point: a **new finding** or a **newly-exposed** server is a
regression; a **resolved finding** or a server that stopped being exposed is an
improvement; new/removed assets are informational. A *disappearing security
control* surfaces as a new finding (the check that the control was present now
fires). `--fail-on-regression` exits non-zero **only** on regressions, so
`diff` drops into CI to block posture backsliding — commit a signed baseline,
then diff every change against it. The baseline's digest is re-verified on load,
so an edited or corrupted baseline is refused rather than trusted. `--json`
emits the full machine-readable drift; `--no-inventory` snapshots posture only.

### Framework mapping (`mcpscan atlas`)

`atlas` renders the same findings `scan` produces, each annotated with its
security-framework citations — **MITRE ATT&CK**, **MITRE ATLAS**, **OWASP LLM
Top 10**, **NIST AI RMF** (function level), and **CIS Controls v8** (control
level) — so a finding drops straight into an assessment report or a GRC tool.

```
$ mcpscan atlas
  [CRITICAL] CRED-PLAINTEXT: Plaintext High-entropy secret in config
             ↳ MITRE ATT&CK T1552.001 — Unsecured Credentials: Credentials In Files
             ↳ MITRE ATLAS AML.T0055 — Unsecured Credentials
             ↳ OWASP LLM Top 10 LLM02 — Sensitive Information Disclosure
             ↳ NIST AI RMF GOVERN — Govern function
             ↳ CIS Controls v8 Control 3 — Data Protection
```

`--matrix` prints the full static check-id → framework table without scanning;
`--json` emits mapped findings plus the matrix. The mapping table is
deliberately conservative — a citation appears only where the technique/control
match is direct, NIST AI RMF stays at function level and CIS at control level —
and it lives in one auditable data file
([`src/mcpscan/atlas/model.py`](src/mcpscan/atlas/model.py)), with CI gating
that every check id the scanner can emit has a mapping and no mapping outlives
its check. Exit-code semantics match `scan` (`--fail-on`).

### GitHub code scanning (SARIF)

`--sarif` writes a SARIF 2.1.0 log that GitHub ingests as code-scanning alerts on
the **Security** tab, with per-finding severity (`security-severity`) and stable
fingerprints so alerts track across commits. Paths inside the scanned repo are
emitted repo-relative so alerts annotate the offending line; secrets are never
present (only the redacted fingerprint). SARIF covers **config-file** findings;
running-socket exposure (no source file) stays in the terminal/JSON/HTML views.
Drop this into a workflow:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: actions/setup-python@v5
    with: { python-version: "3.11" }
  - run: pip install ai-agentic-mcpscan
  - run: mcpscan scan --sarif results.sarif --fail-on critical
    continue-on-error: true
  - uses: github/codeql-action/upload-sarif@v4
    with: { sarif_file: results.sarif }
```

This repo dogfoods it in [`.github/workflows/mcpscan.yml`](.github/workflows/mcpscan.yml).

### Authorized network assessment (`mcpscan lan`)

`mcpscan scan` is localhost-only. `mcpscan lan` is a **separate, gated** command
for assessing MCP exposure on hosts **you are authorized to test** — and it is
**inert without a signed authorization manifest**. Governing principle:
*discovery never converts into authority.* It is exposure-only (never reads a
remote config), private-address by default, and bounded by immutable budgets.

```bash
mcpscan lan --manifest auth.toml \
            --signature auth.toml.sig \
            --allowed-signers allowed_signers \
            --invoker human \
            --dry-run            # verify + print the plan; send no packets
```

The manifest is a signed TOML file naming exact targets, ports, operator, and
expiry:

```toml
authorization_id = "ENG-2026-0710"
operator         = "you@example.com"
expires_at       = "2026-07-10T23:59:59Z"
targets          = ["192.168.10.20/32"]   # exact hosts / /32 (a human may use a capped CIDR)
ports            = [3000, 8000]
```

Sign it with your SSH key (`ssh-keygen -Y sign -n mcpscan-lan -f key auth.toml`).
`--invoker agent` gets tighter budgets and exact-hosts-only. Public targets are
refused unless named in an `--enterprise-policy` file. `--json` and `--sarif`
both work: because a LAN finding's location is a network endpoint (not a source
file), `--sarif` emits it as a SARIF **logical location**
(`kind: resource`, `fullyQualifiedName: lan://host:port`) — standards-valid for
generic SARIF and SIEM/audit consumers, **not** GitHub code scanning (which
needs a checkout file to raise an alert). No synthetic file path is ever
invented; see [ADR-16](docs/DECISIONS.md). Step-by-step:
[`docs/LAN_OPERATOR_GUIDE.md`](docs/LAN_OPERATOR_GUIDE.md); full design and threat
model: [`docs/proposals/LAN_SCANNING.md`](docs/proposals/LAN_SCANNING.md).

## Documentation

| Doc | What it is |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | Full product & technical specification (testable requirements, scoring rubric, threat model, DoD). |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 15 architecture decision records. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component model, dependency direction, trust boundaries. |
| [docs/BACKLOG.md](docs/BACKLOG.md) | Sprint-tagged tickets + requirement→ticket traceability. |
| [docs/SECURITY_SIGNOFF.md](docs/SECURITY_SIGNOFF.md) | Threat-model verification matrix (security sign-off). |
| [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) | Reporting policy · contributor guide. |

## Status & roadmap

**v1.0 is released on [PyPI](https://pypi.org/project/ai-agentic-mcpscan/)** —
stable and production-ready, behind a green CI gate (ruff, mypy --strict, bandit,
pytest with a 90% branch-coverage floor, on macOS/Linux/Windows × Python
3.11–3.13), with SBOM + checksums on every release. The 1.0 bar it shipped
against: SARIF 2.1.0 output + a GitHub code-scanning workflow, opt-in `--fix`
for over-broad tool scopes, **seven** host adapters (Claude, Cursor, Windsurf,
Cline, VS Code, Zed, Continue), `mcpscan lan` — authorized, exposure-only
network assessment behind a signed manifest — and a
[dogfood harness](tools/dogfood/README.md) that gates every check against a
clean+messy corpus across all hosts (0 false positives / 0 false negatives, run
in CI).

From 1.0, the CLI surface, JSON report schema, and check ids are covered by
semver: breaking changes to any of them mean a major version bump.

Roadmap for 1.x, tracking the platform tiers in
[docs/proposals/VISION.md](docs/proposals/VISION.md): **`inventory` (Tier 1),
`atlas` (Tier 2), `trust` (Tier 4), and `baseline`/`diff` drift detection
(Tier 5) have landed** — a classified AI/MCP asset list, findings mapped to
MITRE ATT&CK/ATLAS, OWASP LLM Top 10, NIST AI RMF, and CIS v8, a per-agent Trust
Score with risk relationships, and a CI gate against posture backsliding —
alongside **SARIF logical-location output for non-file (`lan`) findings**
(ADR-16). Next: `graph` (Tier 3 — an AI attack-path graph built on the trust
model) and real-lab dogfooding (stakeholder configs + a pfSense/Suricata network
lab for the socket and `lan` surfaces).

## License

[Apache-2.0](LICENSE).
