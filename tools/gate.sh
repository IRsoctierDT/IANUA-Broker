#!/usr/bin/env bash
# Full local gate. Formats the tree first so "format --check" is a verification
# of work already done, not a surprise CI failure.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "==> ruff format (apply)"
ruff format .
echo "==> ruff check"
ruff check .
echo "==> ruff format --check"
ruff format --check .
echo "==> mypy"
mypy src
echo "==> bandit"
bandit -r src -q
echo "==> pytest"
pytest -q
echo "gate green"
