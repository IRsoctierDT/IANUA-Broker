# Releasing IANUA-Broker

Releases are **automated through release-please** and publish to PyPI via
**Trusted Publishing** (OIDC), so no API token is ever stored in the repo. The
`release-please.yml` workflow maintains a release PR on every push to `main`;
merging that PR tags the release, creates the GitHub Release, and runs the
`publish` job that builds and uploads the distribution to PyPI.

The distribution name on PyPI is **`ianua-broker`**; the import package and CLI
command remain `mcpscan`.

## One-time setup (you, once)

1. **Create the PyPI Trusted Publisher** for the automated path:
   - PyPI → the `ianua-broker` project → *Manage* → *Publishing* → *Add a
     publisher* (or add a *pending publisher* if the project does not exist yet).
   - Owner: `IRsoctierDT` · Repository: `IANUA-Broker`
   - **Workflow filename: `release-please.yml`** (this is the workflow that
     publishes — there is no longer a separate manual `release.yml`).
   - Environment name: `pypi`
2. **(Recommended) Protect the `pypi` environment** in GitHub:
   - Repo → Settings → Environments → `pypi` → add yourself as a required
     reviewer. The actual upload then requires your one-click approval even after
     the release PR is merged.
3. **Allow Actions to open PRs** — Settings → Actions → General → Workflow
   permissions → enable *"Allow GitHub Actions to create and approve pull
   requests"*. Without this, release-please cannot open its release PR.

## Each release

Releases are driven by [Conventional Commits](https://www.conventionalcommits.org/):
`feat:` bumps the minor version, `fix:` the patch, and a `!`/`BREAKING CHANGE`
bumps the major. You never edit the version in `pyproject.toml` by hand.

1. Land your changes on `main` via PRs with Conventional-Commit titles (the
   `pr-title.yml` check enforces this).
2. release-please opens or updates a **release PR** that bumps
   `[project].version` in `pyproject.toml` and updates `CHANGELOG.md`.
   `mcpscan.__version__` derives from the installed package metadata, so there is
   nothing else to keep in sync.
3. When you're ready to ship, **merge the release PR**. release-please tags the
   release, creates the GitHub Release, and the `publish` job builds the
   sdist+wheel and — after your `pypi`-environment approval, if enabled —
   Trusted-Publishes to PyPI. The same `publish` job attaches a CycloneDX SBOM
   and SHA-256 checksums to the Release.
4. Verify: `pipx install ianua-broker` on a clean machine, then `mcpscan
   --version`.

## Notes

- Built artifacts are named `ianua_broker-<version>` and must match the
  `ianua-broker` PyPI project the Trusted Publisher is scoped to.
- To do a dry run first, publish to TestPyPI by adding a `repository-url` to the
  publish step and a corresponding TestPyPI Trusted Publisher.
