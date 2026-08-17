# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Inspection-health check: an installed data-pack store that cannot be trusted.

A data-pack defines what the scanner *counts* as a secret. That makes the
installed store the highest-leverage file on the machine from an attacker's
point of view: they do not need to hide a credential if they can redefine the
patterns that would have found it, and the scan then passes honestly.

``update-datapack`` verifies a signature before installing and writes the store
``0600``, but permissions drift after the fact — an umask, a restored backup, a
synced dotfiles repository, a group-writable parent. So the store's mode is
re-checked on every read, and a store other users can write is refused.

Refusal alone would be fail-safe but silent, and silence is the failure mode
this scanner exists to prevent: the operator would keep seeing clean scans from
a pack that was quietly discarded, or never notice one was tampered with. Hence
this finding, which rides the same ``inspection_incomplete`` signal as
``CONFIG-UNREADABLE`` — the scan is still trustworthy (detection fell back to the
built-in catalog), but the operator is told their refresh channel is not.

Pure over its inputs; the ``stat`` lives in :mod:`mcpscan.datapack`.
"""

from __future__ import annotations

from ..domain import Dimension, Finding, Location, Severity


def check_datapack_store(store_path: str, *, writable_by_others: bool) -> list[Finding]:
    """Flag an installed data-pack store that other local users can write.

    Args:
        store_path: The store's path, as the report should name it.
        writable_by_others: Whether its POSIX mode carries group/other write
            bits (computed by :func:`mcpscan.datapack.store_is_writable_by_others`).

    Returns:
        One HIGH ``DATAPACK-STORE-PERMS`` finding, or an empty list.

        HIGH rather than MEDIUM — unlike an unreadable config, this is not an
        inspection gap but a live tampering surface with a known consequence:
        write access to this file is write access to the detection catalog. It
        fails the default ``--fail-on high`` gate deliberately, and the fix is a
        single ``chmod``.
    """
    if not writable_by_others:
        return []
    return [
        Finding(
            id="DATAPACK-STORE-PERMS",
            dimension=Dimension.TOOL_SCOPE,
            severity=Severity.HIGH,
            title="Detection data-pack store is writable by other users",
            location=Location(path=store_path),
            remediation=(
                "Restrict the store to its owner: chmod 600 the file (and check the "
                "parent directory is not group/world-writable). Then re-run "
                "'mcpscan update-datapack' to reinstall a verified pack."
            ),
            rationale=(
                "This file holds the detection catalog — the patterns, entropy "
                "threshold, and markers that decide what counts as a secret. Any "
                "user who can write it can switch detection off without touching a "
                "single credential, and the scan would still report clean. The "
                "store was refused for this run and detection fell back to the "
                "built-in catalog, so this scan is sound; the refresh channel is not."
            ),
        )
    ]
