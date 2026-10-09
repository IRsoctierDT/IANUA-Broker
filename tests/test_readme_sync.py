# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Guard: README.md's generated sections must match their sources of truth.

``tools/build_readme.py`` renders the option reference, check catalog and
release line from the code that defines them. This test is the CI drift gate:
it fails on every OS/Python cell when a change lands without regenerating the
README. Fix with ``python tools/build_readme.py``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "tools" / "build_readme.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_readme", _TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_readme_generated_sections_are_current() -> None:
    tool = _load()
    _new, changed = tool.regenerate(tool.README.read_text(encoding="utf-8"))
    assert changed == [], f"README.md is stale in {changed}; run: python tools/build_readme.py"


def test_every_cli_option_is_documented() -> None:
    from mcpscan.cli import build_parser

    readme = _load().README.read_text(encoding="utf-8")
    for action in build_parser()._actions:
        for flag in action.option_strings:
            if flag not in ("-h", "--help"):
                assert f"`{flag}" in readme, flag


def test_every_check_id_is_in_the_catalog() -> None:
    from mcpscan.atlas import MAPPINGS

    readme = _load().README.read_text(encoding="utf-8")
    for check_id in MAPPINGS:
        assert f"`{check_id}`" in readme, check_id


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("<!-- BEGIN GENERATED: options -->", ""),
        lambda t: t + "\n<!-- BEGIN GENERATED: bogus -->\nx\n<!-- END GENERATED: bogus -->\n",
        lambda t: t + "\n<!-- BEGIN GENERATED: release -->\nx\n<!-- END GENERATED: release -->\n",
    ],
    ids=["missing", "unknown", "duplicated"],
)
def test_invalid_markers_fail_closed(mutate: object) -> None:
    tool = _load()
    text = tool.README.read_text(encoding="utf-8")
    with pytest.raises(ValueError):
        tool.regenerate(mutate(text))  # type: ignore[operator]


def test_check_mode_reports_stale_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _load()
    stale = tmp_path / "README.md"
    stale.write_text(
        tool.README.read_text(encoding="utf-8").replace(
            "**Current release: v", "**Current release: v0"
        ),
        encoding="utf-8",
    )
    before = stale.read_text(encoding="utf-8")
    monkeypatch.setattr(tool, "README", stale)
    assert tool.main(["--check"]) == 1
    assert stale.read_text(encoding="utf-8") == before
    assert tool.main([]) == 0
    assert tool.main(["--check"]) == 0
