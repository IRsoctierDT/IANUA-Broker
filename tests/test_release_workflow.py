# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Guard: the release workflow builds exactly the tagged commit, one release at a time.

The ``publish`` job runs only when a real release is cut, so a regression in it
surfaces only then: as a tag that never reaches PyPI, or as an artifact that is
not the tagged source. These tests hold its invariants on every run instead:

* release-please is serialized and never cancelled mid-run, so two pushes in
  quick succession cannot both try to create one release (1.11.4's
  ``already_exists`` failure);
* ``publish`` checks out the release tag before building, so the artifact is the
  tagged tree rather than whichever commit triggered the run (1.11.4's sdist was
  built from the commit after its tag);
* the workflow's own resolve and verify scripts, run here as Actions runs them,
  name the tag release-please creates and fail closed on a version mismatch or a
  tag that is not on main;
* the SBOM describes the released wheel and its runtime dependencies, with the
  package as its subject, rather than the CI job's own environment (1.11.5's
  listed 37 build and SBOM tools beside the 2 packages a user installs).
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess  # nosec B404
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW = _ROOT / ".github" / "workflows" / "release-please.yml"
_GIT = shutil.which("git")
_BASH = shutil.which("bash")

_needs_shell = pytest.mark.skipif(
    os.name == "nt" or _GIT is None or _BASH is None,
    reason="the publish job runs its scripts with bash and git on ubuntu-latest",
)


def _jobs() -> dict[str, Any]:
    return dict(yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))["jobs"])


def _publish_steps() -> list[dict[str, Any]]:
    return list(_jobs()["publish"]["steps"])


def _step_index(name: str) -> int:
    names = [step.get("name") for step in _publish_steps()]
    assert name in names, f"publish job has no step named {name!r}"
    return names.index(name)


def _step(name: str) -> dict[str, Any]:
    return _publish_steps()[_step_index(name)]


def test_release_please_runs_one_at_a_time_and_is_never_cancelled() -> None:
    concurrency = _jobs()["release-please"].get("concurrency")
    assert concurrency, "the release-please job must be serialized"
    # release-please acts on the default branch whatever ref triggered it, so a
    # per-ref group would let a dispatch from another branch race a push to main.
    assert "${{" not in str(concurrency["group"]), "the concurrency group must be fixed"
    assert concurrency["cancel-in-progress"] is False


def test_publish_builds_the_tag_only_after_verifying_it() -> None:
    checkout = _step("Check out the tagged release")
    assert checkout["with"]["ref"] == "refs/tags/${{ steps.tag.outputs.name }}"
    assert checkout["with"]["fetch-depth"] == 0  # the main-ancestry check needs history
    verify = _step_index("Verify the tag before building it")
    assert _step_index("Check out the tagged release") < verify
    for later in ("Build distributions", "Publish to PyPI (Trusted Publishing)"):
        assert verify < _step_index(later), f"{later!r} must run after the tag is verified"


def test_publish_keeps_the_token_out_of_git_config() -> None:
    checkouts = [
        s for s in _publish_steps() if str(s.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkouts, "publish must check out the repository"
    for step in checkouts:
        assert step["with"]["persist-credentials"] is False


def test_sbom_describes_the_released_wheel_not_the_build_job() -> None:
    script = _step("Generate CycloneDX SBOM")["run"]
    commands = [shlex.split(line) for line in script.splitlines() if line.strip()]
    env_python = "$RUNNER_TEMP/sbom-env/bin/python"
    # An otherwise empty environment, holding only the wheel being published.
    assert ["python", "-m", "venv", "--without-pip", "$RUNNER_TEMP/sbom-env"] in commands
    assert ["python", "-m", "pip", "--python", env_python, "install", "dist/*.whl"] in commands
    assert ["python", "-m", "pip", "install", "."] not in commands
    sbom = next(c for c in commands if c[:2] == ["cyclonedx-py", "environment"])
    assert sbom[-1] == env_python, "the SBOM must describe that environment, not this job's"
    assert "--pyproject" in sbom, "the package must be the SBOM's subject"


@pytest.fixture
def python_shim(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A directory whose ``python`` runs this interpreter, as setup-python provides.

    A wrapper, not a symlink: a symlink to a venv's interpreter starts the base
    interpreter instead, because Python finds ``pyvenv.cfg`` by the path it was run as.
    """
    shim = tmp_path_factory.mktemp("bin")
    python = shim / "python"
    python.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n', encoding="utf-8")
    python.chmod(0o755)
    return shim


def _bash(
    script: str, cwd: Path, env: dict[str, str], shim: Path
) -> subprocess.CompletedProcess[str]:
    """Run a step's script the way Actions does: ``bash -e``, ``python`` on PATH."""
    assert _BASH is not None
    full_env = {**os.environ, **env}
    full_env["PATH"] = os.pathsep.join([str(shim), full_env["PATH"]])
    return subprocess.run(  # nosec B603 (fixed argv, no shell)
        [_BASH, "-e", "-c", script],
        check=False,
        cwd=cwd,
        env=full_env,
        capture_output=True,
        text=True,
    )


@_needs_shell
def test_resolve_names_the_tag_release_please_creates(tmp_path: Path, python_shim: Path) -> None:
    out = tmp_path / "github_output"
    env = {"GITHUB_OUTPUT": str(out)}
    result = _bash(_step("Resolve release tag")["run"], _ROOT, env, python_shim)
    assert result.returncode == 0, result.stderr
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    outputs = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines())
    assert outputs == {"name": f"ianua-broker-v{project['version']}", "version": project["version"]}


def _git(repo: Path, *args: str) -> str:
    assert _GIT is not None
    done = subprocess.run(  # nosec B603 (fixed argv, no shell)
        [_GIT, "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return done.stdout.strip()


def _commit_version(repo: Path, version: str) -> str:
    (repo / "pyproject.toml").write_text(
        f'[project]\nname = "ianua-broker"\nversion = "{version}"\n', encoding="utf-8"
    )
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-qm", f"release {version}")
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A clone as ``publish`` sees it: v1.2.3 tagged on main, then main moved on.

    A v1.2.4 tag also exists on a side branch that never reached main.
    """
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "tag", "ianua-broker-v1.2.3", _commit_version(tmp_path, "1.2.3"))
    (tmp_path / "later.txt").write_text("the commit after the release\n", encoding="utf-8")
    _git(tmp_path, "add", "later.txt")
    _git(tmp_path, "commit", "-qm", "later")
    _git(tmp_path, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(tmp_path, "checkout", "-q", "-b", "side", "ianua-broker-v1.2.3")
    _git(tmp_path, "tag", "ianua-broker-v1.2.4", _commit_version(tmp_path, "1.2.4"))
    return tmp_path


def _verify(repo: Path, shim: Path, tag: str, version: str) -> subprocess.CompletedProcess[str]:
    step = _step("Verify the tag before building it")
    assert set(step["env"]) == {"TAG", "VERSION"}
    _git(repo, "checkout", "-q", "--detach", f"refs/tags/{tag}")  # the tagged checkout
    return _bash(step["run"], repo, {"TAG": tag, "VERSION": version}, shim)


@_needs_shell
def test_verify_accepts_a_tag_on_main(repo: Path, python_shim: Path) -> None:
    result = _verify(repo, python_shim, "ianua-broker-v1.2.3", "1.2.3")
    assert result.returncode == 0, result.stdout + result.stderr
    tagged = _git(repo, "rev-parse", "ianua-broker-v1.2.3^{commit}")
    assert f"Publishing ianua-broker-v1.2.3 from {tagged}" in result.stdout


@_needs_shell
def test_verify_refuses_a_version_the_tag_does_not_declare(repo: Path, python_shim: Path) -> None:
    result = _verify(repo, python_shim, "ianua-broker-v1.2.3", "1.2.4")
    assert result.returncode != 0
    assert "declares version 1.2.3, not 1.2.4; refusing to publish" in result.stdout


@_needs_shell
def test_verify_refuses_a_tag_that_is_not_on_main(repo: Path, python_shim: Path) -> None:
    result = _verify(repo, python_shim, "ianua-broker-v1.2.4", "1.2.4")
    assert result.returncode != 0
    assert "is not on main; refusing to publish" in result.stdout
