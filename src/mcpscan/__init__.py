# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""IANUA-Broker — local-first MCP security posture scanner.

This package currently contains only the CLI entry-point scaffold. The scanner
engine is built across Sprints 1-4 per ``docs/BACKLOG.md`` after Principal
Architect validation and full-team backlog review.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: the version declared in pyproject.toml, surfaced
    # through the installed package metadata (hatchling reads it from there).
    __version__ = version("ianua-broker")
except PackageNotFoundError:  # pragma: no cover - source tree without an install
    __version__ = "0.0.0+unknown"
