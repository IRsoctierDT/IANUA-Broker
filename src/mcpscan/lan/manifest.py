# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Authorization-manifest parsing (LAN proposal §3.1).

The manifest is a signed TOML file naming the exact targets, ports, operator, and
expiry of an authorized run. This module parses and validates it (stdlib
``tomllib`` — no dependency) and computes its SHA-256 for the audit record. It
never raises: malformed or invalid input returns a :class:`ManifestError`.

Signature verification and expiry enforcement live elsewhere — parsing a manifest
grants nothing on its own.
"""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime

_VALID_SCHEMES = ("ssh", "ed25519")


@dataclass(frozen=True)
class Manifest:
    """A parsed, structurally-valid authorization manifest (not yet verified)."""

    authorization_id: str
    operator: str
    expires_at: datetime  # timezone-aware, normalized to UTC
    targets: tuple[str, ...]  # raw target strings (validated in scope resolution)
    ports: tuple[int, ...]
    signature_scheme: str  # "ssh" (default) | "ed25519"
    sha256: str  # hex digest of the exact manifest bytes

    def is_expired(self, now: datetime) -> bool:
        """True if ``now`` (tz-aware) is at or past ``expires_at``."""
        return now >= self.expires_at


@dataclass(frozen=True)
class ManifestError:
    """A manifest that could not be parsed or failed validation."""

    message: str


def _require_str(data: dict[str, object], key: str) -> str | ManifestError:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        return ManifestError(f"manifest field '{key}' must be a non-empty string")
    return value


def load_manifest(raw: bytes) -> Manifest | ManifestError:
    """Parse and validate manifest bytes into a :class:`Manifest` or error.

    ``raw`` is the exact file content; its SHA-256 is recorded so the audit trail
    and the signature both bind to the same bytes.
    """
    sha256 = hashlib.sha256(raw).hexdigest()
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return ManifestError(f"invalid manifest TOML: {exc}")

    auth_id = _require_str(data, "authorization_id")
    if isinstance(auth_id, ManifestError):
        return auth_id
    operator = _require_str(data, "operator")
    if isinstance(operator, ManifestError):
        return operator

    expires_raw = data.get("expires_at")
    expires_at = _parse_expiry(expires_raw)
    if isinstance(expires_at, ManifestError):
        return expires_at

    targets = _parse_targets(data.get("targets"))
    if isinstance(targets, ManifestError):
        return targets

    ports = _parse_ports(data.get("ports"))
    if isinstance(ports, ManifestError):
        return ports

    scheme = _parse_scheme(data.get("signature"))
    if isinstance(scheme, ManifestError):
        return scheme

    return Manifest(
        authorization_id=auth_id,
        operator=operator,
        expires_at=expires_at,
        targets=targets,
        ports=ports,
        signature_scheme=scheme,
        sha256=sha256,
    )


def _parse_expiry(value: object) -> datetime | ManifestError:
    # tomllib may already yield a datetime (TOML offset/local date-time) or a str.
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return ManifestError(f"expires_at is not a valid ISO-8601 datetime: {value!r}")
    else:
        return ManifestError("manifest field 'expires_at' is required (ISO-8601 datetime)")
    if dt.tzinfo is None:
        return ManifestError("expires_at must include a timezone (e.g. trailing 'Z')")
    return dt.astimezone(UTC)


def _parse_targets(value: object) -> tuple[str, ...] | ManifestError:
    if not isinstance(value, list) or not value:
        return ManifestError("manifest field 'targets' must be a non-empty array")
    if not all(isinstance(t, str) and t.strip() for t in value):
        return ManifestError("every entry in 'targets' must be a non-empty string")
    return tuple(str(t) for t in value)


def _parse_ports(value: object) -> tuple[int, ...] | ManifestError:
    if not isinstance(value, list) or not value:
        return ManifestError("manifest field 'ports' must be a non-empty array")
    ports: list[int] = []
    for p in value:
        # bool is a subclass of int — reject it explicitly.
        if not isinstance(p, int) or isinstance(p, bool) or not (1 <= p <= 65535):
            return ManifestError(f"every port must be an integer in 1..65535, got {p!r}")
        ports.append(p)
    return tuple(ports)


def _parse_scheme(signature: object) -> str | ManifestError:
    if signature is None:
        return "ssh"  # default, dependency-free
    if not isinstance(signature, dict):
        return ManifestError("manifest '[signature]' must be a table")
    scheme = signature.get("scheme", "ssh")
    if scheme not in _VALID_SCHEMES:
        return ManifestError(f"signature.scheme must be one of {_VALID_SCHEMES}, got {scheme!r}")
    return str(scheme)
