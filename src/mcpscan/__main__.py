# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Enable ``python -m mcpscan``.

Generated scheduler units (``mcpscan schedule``) fall back to
``<python> -m mcpscan`` when the ``mcpscan`` console script is not on ``PATH``;
without this module that invocation fails with "No module named mcpscan.__main__".
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
