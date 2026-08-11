# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Dogfood corpus as a CI regression gate (T-402).

Runs the curated clean+messy corpus (tools/dogfood/corpus.py) through the real
scan pipeline and asserts each fixture produces exactly its labeled findings —
so a heuristic regression (a new false positive on a clean config, or a missed
finding on a messy one) fails CI permanently.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools" / "dogfood"))

from corpus import CORPUS, Fixture, evaluate


@pytest.mark.parametrize("fixture", CORPUS, ids=lambda fx: fx.name)
def test_corpus_fixture_matches_label(fixture: Fixture) -> None:
    result = evaluate(fixture)
    assert result.false_positives == frozenset(), (
        f"{fixture.name}: false positive(s) {sorted(result.false_positives)}"
    )
    assert result.false_negatives == frozenset(), (
        f"{fixture.name}: false negative(s) {sorted(result.false_negatives)}"
    )


def test_clean_corpus_is_completely_silent() -> None:
    # The most important property: a well-configured setup produces zero findings.
    for fixture in CORPUS:
        if fixture.label == "clean":
            assert evaluate(fixture).actual == frozenset(), f"{fixture.name} was not silent"


def test_corpus_covers_every_host() -> None:
    hosts = {fx.host for fx in CORPUS}
    assert hosts == {"claude", "cursor", "windsurf", "cline", "vscode", "zed", "continue"}
