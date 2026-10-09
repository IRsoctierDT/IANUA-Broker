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

**Do not hand-edit** `[project].version` in `pyproject.toml`, `.release-please-manifest.json`, or invent a dated `## [x.y.z]` CHANGELOG section on a feature branch. That fights release-please (manifest drift). Put notes under `## [Unreleased]` if you must; the release PR materializes the versioned section.

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

## Choosing the version explicitly (`Release-As`)

To ship a version other than the one Conventional Commits imply (a milestone
major, say), land a commit on `main` whose message ends with the footer
`Release-As: X.Y.Z`. release-please then rewrites its pending release PR to that
version. The footer must survive into the squash commit on `main`, so keep it in
the squash-merge message. Still never edit `pyproject.toml` or the manifest by
hand.

**2.0.0 (milestone):** set this way by the owner after 1.9.1. It marks the live
tool-manifest inspection line (live capture, stdio sandbox, per-tool drift,
mcpseal import, directive detection) as the product's new baseline. No CLI
flag, report format or exit code changed. Upgrade note: 2.0.0 reports
**more findings** on the same servers, because the injection families and the
new `LIVE-TOOL-CROSS-TOOL-DIRECTIVE` check (see [BENCHMARKS.md](BENCHMARKS.md))
fire where earlier versions were silent. With the default `--fail-on high`, the
new high-severity injection families can fail a gate that 1.9.x passed; with
`--fail-on medium`, the medium-severity directive check can too. Review the new
findings; for one that is legitimately flagged, a named owner can record an
acceptance (finding id + server) in `.mcpscan-accept.json`.

## Notes

- Built artifacts are named `ianua_broker-<version>` and must match the
  `ianua-broker` PyPI project the Trusted Publisher is scoped to.
- To do a dry run first, publish to TestPyPI by adding a `repository-url` to the
  publish step and a corresponding TestPyPI Trusted Publisher.
