# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Authorization-manifest signature verification (LAN proposal §3.1).

A LAN run is inert until the manifest's detached signature verifies. Two schemes
are supported (operator decision): ``ssh`` (default, dependency-free) via
``ssh-keygen -Y verify``, and ``ed25519`` — library-based verification behind the
optional ``[crypto]`` extra. If the extra is not installed, an ``ed25519``
manifest is refused with an install hint, never silently downgraded. The verifier
is injectable so tests never shell out.
"""

from __future__ import annotations

import base64
import binascii

# Justification for the bandit suppressions below: ssh-keygen is invoked with a
# fixed argument vector and shell=False, so nothing here is shell-interpreted; the
# only variable inputs (operator, file paths) are passed as argv items, not a
# command string, and cannot inject.
import subprocess  # nosec B404
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .sanitize import sanitize_remote

SSH_NAMESPACE = "mcpscan-lan"
_CRYPTO_HINT = "install the '[crypto]' extra (pip install ianua-broker[crypto]) for ed25519"

# (manifest_bytes, signature_path, allowed_signers, operator) -> VerifyResult
Verifier = Callable[[bytes, Path, Path, str], "VerifyResult"]


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of verifying a manifest signature."""

    ok: bool
    detail: str


def verify_ssh(
    manifest_bytes: bytes,
    signature_path: Path,
    allowed_signers: Path,
    operator: str,
) -> VerifyResult:
    """Verify a detached SSH signature over the manifest via ``ssh-keygen``.

    Runs ``ssh-keygen -Y verify`` with a fixed argument vector (no shell), the
    signature and allowed-signers files, the operator identity, and a fixed
    namespace. The manifest bytes are fed on stdin so the signature binds to the
    exact content that was parsed.
    """
    cmd = [
        "ssh-keygen",
        "-Y",
        "verify",
        "-f",
        str(allowed_signers),
        "-I",
        operator,
        "-n",
        SSH_NAMESPACE,
        "-s",
        str(signature_path),
    ]
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            input=manifest_bytes,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        return VerifyResult(False, "ssh-keygen not found; install OpenSSH to use the 'ssh' scheme")
    except (OSError, subprocess.SubprocessError) as exc:
        return VerifyResult(False, f"signature verification could not run: {exc}")

    if proc.returncode == 0:
        return VerifyResult(True, "signature verified (ssh)")
    # ssh-keygen output is external; sanitize before surfacing.
    detail = sanitize_remote(proc.stderr or proc.stdout or b"verification failed", max_len=160)
    return VerifyResult(False, f"signature rejected: {detail}")


def _ed25519_pubkey_for(signers_text: str, operator: str) -> bytes | str:
    """Return the operator's raw Ed25519 public key from an allowed-signers file.

    Format (one per line): ``<operator> <base64 raw 32-byte public key>``. Returns
    an error string when the operator is absent or the key is malformed.
    """
    for raw_line in signers_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == operator:
            try:
                return base64.b64decode(parts[1], validate=True)
            except (binascii.Error, ValueError):
                return f"malformed ed25519 public key for operator {operator!r}"
    return f"no ed25519 public key for operator {operator!r} in allowed-signers"


def verify_ed25519(
    manifest_bytes: bytes,
    signature_path: Path,
    allowed_signers: Path,
    operator: str,
) -> VerifyResult:
    """Verify a base64 Ed25519 signature over the manifest (``[crypto]`` extra).

    The signature file holds the base64-encoded raw signature; the allowed-signers
    file maps the operator identity to its base64 raw public key. Refused with an
    install hint if the ``cryptography`` library is not present.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return VerifyResult(False, _CRYPTO_HINT)

    try:
        signature_b64 = signature_path.read_bytes()
        signers_text = allowed_signers.read_text(encoding="utf-8")
    except OSError as exc:
        return VerifyResult(False, f"cannot read signature/allowed-signers: {exc}")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return VerifyResult(False, "ed25519 signature is not valid base64")

    pubkey = _ed25519_pubkey_for(signers_text, operator)
    if isinstance(pubkey, str):
        return VerifyResult(False, pubkey)

    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, manifest_bytes)
    except InvalidSignature:
        return VerifyResult(False, "signature rejected: ed25519 verification failed")
    except ValueError as exc:  # wrong key/signature length
        return VerifyResult(False, f"ed25519 verification error: {exc}")
    return VerifyResult(True, "signature verified (ed25519)")


_DEFAULT_VERIFIERS: dict[str, Verifier] = {"ssh": verify_ssh, "ed25519": verify_ed25519}


def verify_manifest(
    *,
    scheme: str,
    manifest_bytes: bytes,
    signature_path: Path | None,
    allowed_signers: Path | None,
    operator: str,
    verifier: Verifier | None = None,
) -> VerifyResult:
    """Verify a manifest under its declared scheme (dispatch + fail-closed)."""
    if scheme not in _DEFAULT_VERIFIERS:  # pragma: no cover - manifest validation constrains this
        return VerifyResult(False, f"unsupported signature scheme {scheme!r}")
    if signature_path is None or allowed_signers is None:
        return VerifyResult(
            False, f"the {scheme!r} scheme requires --signature and --allowed-signers"
        )
    verify = verifier or _DEFAULT_VERIFIERS[scheme]
    return verify(manifest_bytes, signature_path, allowed_signers, operator)
