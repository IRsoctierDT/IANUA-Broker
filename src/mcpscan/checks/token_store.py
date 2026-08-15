# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Token/credential-store grading (Wave 2 Feature H), pure over its inputs.

Grades the on-disk credential stores named by each host adapter's shared
credential-artifact registry (``HostAdapter.credential_artifact_paths``):

- ``TOKEN-STORE-PERMS`` — the store file is group/world-readable, so any other
  local user or process can steal the token at rest (HIGH).
- ``TOKEN-STORE-EXPIRED`` — an opt-in, offline JWT decode found a token whose
  ``exp`` is already in the past; a stale token lingering at rest widens the
  exposure window with no upside (INFO).

Determinism: every function here is a pure function of its arguments — the I/O
(stat, read) lives in the engine, and "now" is a ``now_epoch`` integer passed
down from ``cli`` so no clock is read here (nor anywhere outside ``cli``).

Redaction: the raw token never leaves the decode boundary. :func:`decode_jwt_unverified`
returns only a :class:`TokenInfo` of non-secret metadata (``exp``/``scopes``/
``present``) — no field holds the token string — and the signature is *never*
verified (that is not this tool's job). Presence with safe permissions and no
decode is not a vulnerability, so it yields no finding.
"""

from __future__ import annotations

import base64
import json
import math
from collections.abc import Iterator
from dataclasses import dataclass

from ..domain import Dimension, Finding, Location, Severity


@dataclass(frozen=True)
class TokenInfo:
    """Non-secret metadata recovered from an unverified JWT decode.

    Intentionally holds no token material: only the expiry (``exp``, seconds
    since the epoch per RFC 7519), any declared scopes, and whether a payload was
    present at all. Scopes are parsed for a future over-broad-scope check but are
    not graded yet (that would over-reach this wave).
    """

    exp: int | None
    scopes: tuple[str, ...]
    present: bool


def _b64url_decode(segment: str) -> bytes:
    """Base64url-decode a JWT segment, restoring the stripped ``=`` padding."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _coerce_scopes(value: object) -> tuple[str, ...]:
    """Normalize a JWT ``scope`` claim (space-delimited string or list) to a tuple."""
    if isinstance(value, str):
        return tuple(value.split())
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


def decode_jwt_unverified(token: str) -> TokenInfo | None:
    """Decode a JWT's payload **without verifying its signature**, offline.

    Splits on ``.``, base64url-decodes the middle (payload) segment, and extracts
    ``exp`` and ``scope`` if present. Returns ``None`` for anything that is not a
    three-segment JWT with a JSON-object payload — a malformed or opaque token
    degrades to "no decode", never an exception. The raw token is never stored:
    the return value carries only :class:`TokenInfo` metadata.
    """
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    raw_exp = payload.get("exp")
    exp: int | None = None
    if isinstance(raw_exp, bool):
        exp = None  # a bool is not a real numeric exp
    elif isinstance(raw_exp, float) and not math.isfinite(raw_exp):
        exp = None  # Infinity/NaN (json.loads accepts them) is not a real expiry
    elif isinstance(raw_exp, (int, float)):
        exp = int(raw_exp)
    return TokenInfo(exp=exp, scopes=_coerce_scopes(payload.get("scope")), present=True)


def _iter_strings(data: object) -> Iterator[str]:
    """Yield every string value nested anywhere in a parsed-JSON structure."""
    if isinstance(data, str):
        yield data
    elif isinstance(data, dict):
        for value in data.values():
            yield from _iter_strings(value)
    elif isinstance(data, list):
        for value in data:
            yield from _iter_strings(value)


def decode_store(raw: str) -> TokenInfo | None:
    """Find and decode the first JWT in a raw token-store file. ``None`` if none.

    Handles both shapes a store can take: a bare JWT written as the whole file,
    or a JSON object with a token string nested somewhere inside (e.g. an OAuth
    record's ``accessToken``/``id_token``). Pure and total — malformed input
    yields ``None`` rather than raising. The raw token is only ever handed to
    :func:`decode_jwt_unverified`, which retains none of it.
    """
    stripped = raw.strip().strip("'\"")
    info = decode_jwt_unverified(stripped)
    if info is not None:
        return info
    try:
        data = json.loads(raw)
        for value in _iter_strings(data):
            info = decode_jwt_unverified(value)
            if info is not None:
                return info
    except (ValueError, json.JSONDecodeError):
        return None
    except RecursionError:
        # Deeply-nested JSON overflows either the decoder or the recursive
        # ``_iter_strings`` walk — both are inside the guard. RecursionError is a
        # RuntimeError, not a ValueError, so "malformed input yields None rather
        # than raising" needs it named explicitly.
        return None
    return None


def _perms_finding(path: str) -> Finding:
    return Finding(
        id="TOKEN-STORE-PERMS",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.HIGH,
        title="Token/credential store is group/world-readable",
        location=Location(path=path),
        remediation="Restrict permissions: chmod 600 the file.",
        rationale=(
            "Any other local user or process can read the stored token and "
            "reuse it — a credential at rest is only as safe as the file mode."
        ),
    )


def _expired_finding(path: str) -> Finding:
    return Finding(
        id="TOKEN-STORE-EXPIRED",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.INFO,
        title="Stale token at rest",
        location=Location(path=path),
        remediation="Rotate or remove the expired token from the store.",
        rationale=(
            "The stored token's expiry (exp) is already in the past. A stale "
            "token left at rest only widens the credential-exposure window."
        ),
    )


def check_token_store(
    path: str,
    mode: int | None,
    present: bool,
    decoded: TokenInfo | None = None,
    *,
    now_epoch: int | None = None,
) -> list[Finding]:
    """Grade one credential/token store from already-gathered facts.

    Args:
        path: The store's path (for the finding location).
        mode: POSIX permission bits (``st_mode & 0o777``), or ``None`` if unknown.
        present: Whether the store file actually exists. A missing store is never
            a finding.
        decoded: An optional :class:`TokenInfo` from an opt-in offline decode.
        now_epoch: "Now" in seconds since the epoch, supplied by ``cli`` so this
            check reads no clock. Required to grade expiry; when ``None`` the
            expiry rule is simply skipped.

    Returns:
        ``TOKEN-STORE-PERMS`` (HIGH) when the file is group/world-readable, and
        ``TOKEN-STORE-EXPIRED`` (INFO) when a decoded token has already expired.
        Mere presence with safe permissions and no decode yields no finding —
        a credential store existing is not itself a vulnerability.
    """
    findings: list[Finding] = []
    if not present:
        return findings
    if mode is not None and mode & 0o077:
        findings.append(_perms_finding(path))
    if (
        decoded is not None
        and decoded.exp is not None
        and now_epoch is not None
        and decoded.exp < now_epoch
    ):
        findings.append(_expired_finding(path))
    return findings
