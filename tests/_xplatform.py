# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Cross-platform test helpers.

Path separators and POSIX file-mode bits differ on Windows CI, and asserting a
``/``-joined path suffix or a world/group-readable mode directly has repeatedly
broken there (Waves 2–3, the graph feature). Centralize the two recurring
patterns so tests reach for these instead of re-deriving them each time.
"""

from __future__ import annotations

import os

import pytest

#: True on POSIX (Linux/macOS). Use for *conditional expectations* — a check
#: whose finding only fires where file modes are meaningful — e.g.
#: ``expected = {"CRED-PLAINTEXT"} | ({"CRED-PERMS"} if POSIX else set())``.
POSIX = os.name == "posix"

#: Skip a whole test that only makes sense under POSIX file semantics (a
#: world/group-readable mode a Windows ``chmod`` cannot express).
posix_only = pytest.mark.skipif(
    not POSIX,
    reason="POSIX file semantics (world/group-readable mode bits) — Windows chmod is a no-op",
)


def id_endswith(value: str, suffix: str) -> bool:
    """True if ``value`` ends with ``suffix``, comparing separators agnostically.

    A server/asset id or a filesystem path carries the host's separator
    (backslashes on Windows); the expected ``suffix`` is written with forward
    slashes. Normalizing before the compare keeps the assertion portable.
    """
    return value.replace("\\", "/").endswith(suffix)
