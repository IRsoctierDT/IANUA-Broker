# Contributing to AI Agentic MCPscan

Thanks for your interest! This project aims to be exemplary, reviewable security
tooling, so contributions are held to a clear bar.

## Quick start

```bash
git clone https://github.com/IRsoctierDT/IANUA-Broker.git
cd IANUA-Broker
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Run the full gate before opening a PR

**Root cause of the common red CI matrix:** commits that never ran `ruff format`
(API pushes, skipped hooks, or only running `format --check`). CI then fails
`ruff format --check` on every OS/Python cell before pytest starts.

Do this instead:

```bash
# one-time — installs a commit hook that auto-formats
python -m pip install pre-commit
pre-commit install

# every change — apply format, then verify (or just:)
./tools/gate.sh
```

Equivalent manual steps:

```bash
ruff format .            # APPLY formatting (required)
ruff check .             # lint
ruff format --check .    # verify nothing drifted
mypy src                 # types (strict)
bandit -r src            # SAST
pytest                   # tests
```

CI runs the same verify gate on macOS, Linux, and Windows across Python 3.11–3.13.
All of it must be green. Prefer `./tools/gate.sh` over assembling the commands by hand.

## Architecture & where things go

- The design is documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
  Read it first — the dependency direction (pure core, I/O at the edges) is
  intentional.
- **New host support** → add a `HostAdapter` in `src/mcpscan/adapters/`. The
  engine and checks must not need to change.
- **New check** → add a small, single-responsibility function in
  `src/mcpscan/checks/`, plus a **clean/negative fixture** (an input that must
  produce zero findings) alongside the positive test. False positives are
  treated as bugs.
- **Anything touching the network** belongs only in `src/mcpscan/enrichment/`
  and must stay behind `--online`.

## Non-negotiables (will block a PR)

- No raw secret value may reach output, logs, or disk. Route secrets through
  `redaction`.
- No egress on a default (non-`--online`) run.
- No writing to a user's config files (advise-only).
- New logic ships with tests, including failure/edge cases.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`) scoped where
useful (e.g. `feat(checks): …`). PR titles are checked against this format by
CI. To get a helpful template in your editor:

```bash
git config commit.template .gitmessage
```

## Workflow, branching & releases

The full Git workflow, CI/CD pipeline, branch-protection settings, semantic
versioning, rollback, and release process are documented in
[`docs/DEVSECOPS.md`](docs/DEVSECOPS.md). In short: branch `feature/*` off
`main`, keep it short-lived, open a PR, get CI green + one review, and squash-merge.

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
