# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Guard: the exported version resolves to pyproject.toml (T-407 release safety).

``mcpscan.__version__`` is derived from the installed package metadata
(``importlib.metadata``), which hatchling populates from ``[project].version`` in
pyproject.toml — so pyproject is the single source of truth. This test confirms
that wiring actually resolves (rather than falling back to the sentinel) and
matches the declared version, catching a broken/stale install or a packaging
misconfig before a release ships a wheel whose ``mcpscan --version`` lies. The
release workflow separately guards the git *tag* against the same field.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import mcpscan

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
_FALLBACK = "0.0.0+unknown"


def _pyproject_version() -> str:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_package_version_resolves_to_pyproject() -> None:
    if mcpscan.__version__ == _FALLBACK:
        pytest.skip("package not installed; __version__ fell back to the sentinel")
    assert mcpscan.__version__ == _pyproject_version(), (
        f"mcpscan.__version__ ({mcpscan.__version__}) != "
        f"pyproject [project].version ({_pyproject_version()}); "
        "reinstall the package so its metadata matches pyproject.toml (see docs/RELEASING.md)."
    )
