# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Objective B — attack the scanner through the filesystem it walks.

The scanner opens files it did not create, at paths it did not choose, in
directories anyone can write to. ``io_safe.safe_read_text`` is the single choke
point for that, and the properties it owes its callers (SPEC NFR-SEC3, NFR-S3)
are narrow enough to enumerate:

- a resolved path must stay inside the permitted root (no symlink escape, no
  ``..`` traversal);
- an oversized file is refused **before** it is read;
- an unreadable file is a typed ``SafeReadError`` — the one exception type every
  caller catches — never a bare ``OSError``, ``RuntimeError``, or a hang.

The last one is where the interesting attacks live. Two shapes defeat a size
cap entirely, because neither has a meaningful size: a **symlink loop**, which
makes path resolution itself fail, and a **FIFO**, which reports ``st_size == 0``
and then blocks forever on read. A ``.mcp.json`` is a predictable filename in a
repository anyone can send you.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from _xplatform import posix_only

from adversarial.corpus import FAKE_ANTHROPIC_KEY, deep_json
from mcpscan.io_safe import (
    DEFAULT_MAX_BYTES,
    FileAccessError,
    FileTooLargeError,
    SafeReadError,
    UnsafeSymlinkError,
    safe_read_text,
)

pytestmark = pytest.mark.filterwarnings("error")


def _read_with_deadline(path: Path, root: Path, seconds: float = 5.0) -> object:
    """Call ``safe_read_text`` on a worker thread and fail if it does not return.

    A blocking read cannot be interrupted from the calling thread, so the test
    asserts on *liveness*: the daemon thread is abandoned if it hangs, and the
    assertion fails rather than the suite stalling forever.
    """
    box: dict[str, object] = {}

    def run() -> None:
        try:
            box["result"] = safe_read_text(path, root=root)
        except BaseException as exc:  # noqa: BLE001 - the outcome IS the result
            box["result"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=seconds)
    assert not worker.is_alive(), (
        f"safe_read_text({path.name}) did not return within {seconds}s — a planted "
        "non-regular file hangs the scan (DoS row of the SPEC §8 threat model)"
    )
    return box["result"]


# --- non-regular files: the size cap cannot see them -------------------------
@posix_only
def test_fifo_config_is_refused_not_awaited(tmp_path: Path) -> None:
    """A named pipe planted as a config is refused, not read.

    With no writer on the other end, ``open()`` blocks indefinitely — a
    zero-byte file that stops the scan forever. ``st_size`` is 0, so only a
    file-*type* check can catch it.
    """
    fifo = tmp_path / ".mcp.json"
    os.mkfifo(fifo)
    result = _read_with_deadline(fifo, tmp_path)
    assert isinstance(result, FileAccessError)


@posix_only
def test_device_file_is_refused(tmp_path: Path) -> None:
    """A character device (``/dev/zero``) inside the root reads as infinite bytes."""
    root = Path("/dev")
    result = _read_with_deadline(Path("/dev/zero"), root)
    assert isinstance(result, FileAccessError)


def test_directory_named_like_a_config_is_refused(tmp_path: Path) -> None:
    """A directory where a file is expected is a typed refusal."""
    (tmp_path / ".mcp.json").mkdir()
    with pytest.raises(SafeReadError):
        safe_read_text(tmp_path / ".mcp.json", root=tmp_path)


# --- symlinks: escape and resolution failure ---------------------------------
@posix_only
def test_symlink_loop_is_a_typed_error(tmp_path: Path) -> None:
    """A symlink cycle fails during resolution, before any invariant is checked.

    ``Path.resolve()`` raises ``RuntimeError`` (POSIX) / ``OSError`` (ELOOP) —
    neither is a ``SafeReadError``, so without an explicit guard the engine's
    ``except SafeReadError`` misses it and the scan dies on a two-symlink trap.
    """
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.symlink_to(b)
    b.symlink_to(a)
    with pytest.raises(SafeReadError):
        safe_read_text(a, root=tmp_path)


@posix_only
def test_symlink_escaping_the_root_is_refused(tmp_path: Path) -> None:
    """The classic escape: a config symlinked at the operator's private key."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret_file = outside / "id_ed25519"
    secret_file.write_text("PRIVATE KEY MATERIAL", encoding="utf-8")

    root = tmp_path / "repo"
    root.mkdir()
    link = root / ".mcp.json"
    link.symlink_to(secret_file)

    with pytest.raises(UnsafeSymlinkError):
        safe_read_text(link, root=root)


@posix_only
def test_symlink_inside_the_root_is_allowed(tmp_path: Path) -> None:
    """The refusal is about escaping, not about symlinks — no false positive."""
    target = tmp_path / "real.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / ".mcp.json"
    link.symlink_to(target)
    assert safe_read_text(link, root=tmp_path) == "{}"


def test_dotdot_traversal_is_refused(tmp_path: Path) -> None:
    """A ``..`` path that climbs out of the root is refused after resolution."""
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside.json").write_text("{}", encoding="utf-8")
    with pytest.raises(UnsafeSymlinkError):
        safe_read_text(root / ".." / "outside.json", root=root)


@posix_only
def test_dangling_symlink_is_a_typed_error(tmp_path: Path) -> None:
    """A link to a file that does not exist is an access error, not a crash."""
    link = tmp_path / ".mcp.json"
    link.symlink_to(tmp_path / "never-created.json")
    with pytest.raises(SafeReadError):
        safe_read_text(link, root=tmp_path)


# --- size and content --------------------------------------------------------
def test_oversized_file_is_refused_before_it_is_read(tmp_path: Path) -> None:
    """The cap is enforced on ``st_size``, so the bytes are never loaded."""
    big = tmp_path / ".mcp.json"
    big.write_text("x" * 2048, encoding="utf-8")
    with pytest.raises(FileTooLargeError):
        safe_read_text(big, root=tmp_path, max_bytes=1024)


def test_cap_default_is_the_documented_five_megabytes() -> None:
    """NFR-S3 names 5 MB; a silent bump would widen every read path at once."""
    assert DEFAULT_MAX_BYTES == 5 * 1024 * 1024


def test_a_file_at_exactly_the_cap_is_read(tmp_path: Path) -> None:
    """Off-by-one guard: the cap is inclusive, so a legitimate file at the
    boundary is not refused."""
    path = tmp_path / ".mcp.json"
    path.write_bytes(b"a" * 1024)
    assert safe_read_text(path, root=tmp_path, max_bytes=1024) == "a" * 1024


def test_binary_content_degrades_to_replacement_characters(tmp_path: Path) -> None:
    """Invalid UTF-8 is replaced, so a binary file becomes a parse error upstream
    rather than a ``UnicodeDecodeError`` nobody catches."""
    path = tmp_path / ".mcp.json"
    path.write_bytes(b"\xff\xfe\x00\x01 not utf-8 \x80\x81")
    text = safe_read_text(path, root=tmp_path)
    assert "�" in text


@posix_only
def test_permission_denied_is_a_typed_error(tmp_path: Path) -> None:
    """An unreadable file is a refusal — not a traceback, and not a skip."""
    if os.geteuid() == 0:
        pytest.skip("root bypasses file permission bits")
    path = tmp_path / ".mcp.json"
    path.write_text("{}", encoding="utf-8")
    path.chmod(0o000)
    try:
        with pytest.raises(FileAccessError):
            safe_read_text(path, root=tmp_path)
    finally:
        path.chmod(0o600)


def test_missing_file_is_a_typed_error(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError):
        safe_read_text(tmp_path / "nope.json", root=tmp_path)


# --- the engine inherits every one of these ----------------------------------
@posix_only
def test_scan_completes_over_a_root_full_of_traps(tmp_path: Path) -> None:
    """A project root seeded with every filesystem trap still produces a report.

    This is the integration form of the module: the traps are planted under the
    exact filenames the scanner looks for, so each one is actually reached.
    """
    from mcpscan.engine import scan

    # A home separate from the project root, so user-level candidate paths
    # (``~/.cursor/mcp.json`` and friends) cannot collide with the traps below
    # and double-count them.
    home = tmp_path / "home"
    home.mkdir()

    os.mkfifo(tmp_path / ".env")  # blocks forever if read

    (tmp_path / ".vscode").mkdir()
    loop_a = tmp_path / ".vscode" / "mcp.json"
    loop_b = tmp_path / ".vscode" / "other.json"
    loop_a.symlink_to(loop_b)
    loop_b.symlink_to(loop_a)

    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").mkdir()  # a directory, not a file

    outside = tmp_path / "outside.json"
    outside.write_text(f'{{"k": "{FAKE_ANTHROPIC_KEY}"}}', encoding="utf-8")
    (tmp_path / ".zed").mkdir()
    (tmp_path / ".zed" / "settings.json").symlink_to(outside)

    (tmp_path / ".mcp.json").write_text(deep_json(), encoding="utf-8")

    box: dict[str, object] = {}

    def run() -> None:
        box["report"] = scan(
            roots=[tmp_path], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False
        )

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=30.0)
    assert not worker.is_alive(), "scan hung on a planted non-regular file"

    report = box["report"]
    ids = [f.id for s in report.servers for f in s.findings]  # type: ignore[attr-defined]
    # Every trap is surfaced as an un-inspected surface rather than skipped.
    assert ids.count("CONFIG-UNREADABLE") == 5
    assert all(
        s.inspection_incomplete
        for s in report.servers  # type: ignore[attr-defined]
        if any(f.id == "CONFIG-UNREADABLE" for f in s.findings)
    )
    # And the symlinked-outside file's contents never made it into the report.
    assert FAKE_ANTHROPIC_KEY not in repr(report)
