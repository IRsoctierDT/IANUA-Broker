"""Token/credential-store check + offline JWT decode (Wave 2 Feature H).

The check is pure over its inputs; "now" is always an injected ``now_epoch``.
The decode is signature-unverified, offline, and never retains the raw token.
"""

from __future__ import annotations

import base64
import json

from mcpscan.adapters.claude import ClaudeAdapter
from mcpscan.adapters.cursor import CursorAdapter
from mcpscan.checks.token_store import (
    TokenInfo,
    check_token_store,
    decode_jwt_unverified,
    decode_store,
)
from mcpscan.domain import Dimension, Severity

# A long-past exp so it is expired against any realistic injected "now".
_PAST = 1_000_000_000  # 2001-09-09
_FUTURE = 4_000_000_000  # 2096
_NOW = 2_000_000_000  # 2033


def _jwt(payload: dict[str, object]) -> str:
    """Build an (unsigned) three-segment JWT carrying ``payload``."""

    def seg(obj: dict[str, object]) -> str:
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg(payload)}.signaturebytes"


# --- check_token_store: permissions ---
def test_world_readable_store_flags_perms_high() -> None:
    findings = check_token_store("/creds.json", 0o644, present=True)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "TOKEN-STORE-PERMS"
    assert f.dimension is Dimension.CREDENTIAL
    assert f.severity is Severity.HIGH
    assert "chmod 600" in f.remediation


def test_group_readable_store_flags_perms() -> None:
    # group-read only (0o040) still trips the 0o077 mask.
    assert any(f.id == "TOKEN-STORE-PERMS" for f in check_token_store("/c", 0o640, present=True))


def test_safe_perm_store_yields_no_finding() -> None:
    # Presence with 0o600 and no decode is not a vulnerability.
    assert check_token_store("/creds.json", 0o600, present=True) == []


def test_unknown_mode_yields_no_perms_finding() -> None:
    assert check_token_store("/creds.json", None, present=True) == []


def test_absent_store_never_finds() -> None:
    assert check_token_store("/creds.json", 0o644, present=False) == []


# --- check_token_store: expiry ---
def test_expired_token_flags_info_only() -> None:
    decoded = decode_jwt_unverified(_jwt({"exp": _PAST}))
    findings = check_token_store("/c", 0o600, present=True, decoded=decoded, now_epoch=_NOW)
    assert [f.id for f in findings] == ["TOKEN-STORE-EXPIRED"]
    assert findings[0].severity is Severity.INFO
    assert findings[0].dimension is Dimension.CREDENTIAL


def test_valid_token_does_not_flag_expiry() -> None:
    decoded = decode_jwt_unverified(_jwt({"exp": _FUTURE}))
    assert check_token_store("/c", 0o600, present=True, decoded=decoded, now_epoch=_NOW) == []


def test_expiry_boundary_is_strict() -> None:
    # exp == now is NOT past; only exp < now expires.
    decoded = decode_jwt_unverified(_jwt({"exp": _NOW}))
    assert check_token_store("/c", 0o600, present=True, decoded=decoded, now_epoch=_NOW) == []


def test_expiry_skipped_without_now_epoch() -> None:
    # No injected clock -> no expiry grade (determinism guardrail).
    decoded = decode_jwt_unverified(_jwt({"exp": _PAST}))
    assert check_token_store("/c", 0o600, present=True, decoded=decoded, now_epoch=None) == []


def test_token_without_exp_never_expires() -> None:
    decoded = decode_jwt_unverified(_jwt({"scope": "read"}))
    assert decoded is not None and decoded.exp is None
    assert check_token_store("/c", 0o600, present=True, decoded=decoded, now_epoch=_NOW) == []


def test_perms_and_expiry_can_both_fire() -> None:
    decoded = decode_jwt_unverified(_jwt({"exp": _PAST}))
    ids = {f.id for f in check_token_store("/c", 0o644, True, decoded, now_epoch=_NOW)}
    assert ids == {"TOKEN-STORE-PERMS", "TOKEN-STORE-EXPIRED"}


# --- decode_jwt_unverified ---
def test_decode_non_finite_exp_is_ignored_not_crashed() -> None:
    # json.loads accepts Infinity/NaN as floats; int(inf)/int(nan) would raise.
    # A non-finite exp must degrade to "no expiry", never abort the scan.
    for bad in (float("inf"), float("-inf"), float("nan")):
        info = decode_jwt_unverified(_jwt({"exp": bad}))
        assert info is not None and info.exp is None
    # And it must not spuriously flag TOKEN-STORE-EXPIRED.
    decoded = decode_jwt_unverified(_jwt({"exp": float("inf")}))
    assert check_token_store("/c", 0o600, True, decoded, now_epoch=_NOW) == []


def test_decode_extracts_exp_and_scopes_from_string_scope() -> None:
    info = decode_jwt_unverified(_jwt({"exp": _PAST, "scope": "read write admin"}))
    assert info == TokenInfo(exp=_PAST, scopes=("read", "write", "admin"), present=True)


def test_decode_extracts_scopes_from_list() -> None:
    info = decode_jwt_unverified(_jwt({"scope": ["a", "b"]}))
    assert info is not None and info.scopes == ("a", "b")


def test_decode_scopes_default_empty() -> None:
    info = decode_jwt_unverified(_jwt({"exp": _FUTURE}))
    assert info is not None and info.scopes == ()


def test_decode_never_returns_raw_token() -> None:
    # The redaction stance: no field or repr of the result holds the token.
    token = _jwt({"exp": _PAST, "secret_claim": "sk-ant-super-secret-value"})
    info = decode_jwt_unverified(token)
    assert info is not None
    assert token not in repr(info)
    assert "sk-ant-super-secret-value" not in repr(info)
    # Structurally: only the three metadata fields exist.
    assert set(vars(info)) == {"exp", "scopes", "present"}


def test_decode_bool_exp_is_ignored() -> None:
    # A JSON bool is a subclass of int but is not a real numeric exp.
    info = decode_jwt_unverified(_jwt({"exp": True}))
    assert info is not None and info.exp is None


def test_decode_float_exp_is_truncated_to_int() -> None:
    info = decode_jwt_unverified(_jwt({"exp": 1234.9}))
    assert info is not None and info.exp == 1234


def test_decode_rejects_non_jwt_shapes() -> None:
    assert decode_jwt_unverified("not-a-jwt") is None  # 1 segment
    assert decode_jwt_unverified("a.b") is None  # 2 segments
    assert decode_jwt_unverified("a..c") is None  # empty middle segment
    assert decode_jwt_unverified("!!!.@@@.###") is None  # undecodable payload


def test_decode_rejects_non_object_payload() -> None:
    # A payload that decodes to JSON but is not an object.
    seg = base64.urlsafe_b64encode(b"[1, 2, 3]").rstrip(b"=").decode("ascii")
    assert decode_jwt_unverified(f"h.{seg}.s") is None


# --- decode_store: file-level extraction ---
def test_decode_store_reads_bare_jwt_file() -> None:
    info = decode_store(_jwt({"exp": _PAST}))
    assert info is not None and info.exp == _PAST


def test_decode_store_reads_quoted_bare_jwt() -> None:
    info = decode_store(f'"{_jwt({"exp": _FUTURE})}"')
    assert info is not None and info.exp == _FUTURE


def test_decode_store_finds_nested_json_token() -> None:
    # Claude Code's shape: a nested OAuth record holding an access token. The
    # dotted "issuer" ensures whole-file decode fails so the JSON walk runs.
    raw = json.dumps(
        {
            "issuer": "auth.anthropic.com",
            "claudeAiOauth": {"accessToken": _jwt({"exp": _PAST}), "refreshToken": "x"},
        }
    )
    info = decode_store(raw)
    assert info is not None and info.exp == _PAST


def test_decode_store_finds_jwt_nested_in_json_list() -> None:
    # A token nested inside a JSON array (exercises the list-walk branch); the
    # dotted "issuer" keeps the whole-file decode from short-circuiting.
    raw = json.dumps({"issuer": "auth.anthropic.com", "tokens": [_jwt({"exp": _FUTURE})]})
    info = decode_store(raw)
    assert info is not None and info.exp == _FUTURE


def test_decode_store_none_for_json_without_a_jwt() -> None:
    # Mixed leaves (number, null, a fully-walked string list) but no JWT anywhere.
    raw = json.dumps(
        {
            "expires_at": 1699999999,
            "v": None,
            "scopes": ["read", "write"],
            "claudeAiOauth": {"accessToken": "sk-ant-oat-opaque"},
        }
    )
    assert decode_store(raw) is None


def test_decode_store_none_for_garbage() -> None:
    # Malformed store degrades to no decode, never raises.
    assert decode_store("%%% not json and not a jwt %%%") is None
    assert decode_store("") is None


# --- adapter credential-artifact registry ---
def test_claude_adapter_registers_credential_path_on_posix() -> None:
    paths = ClaudeAdapter().credential_artifact_paths("Linux", {"HOME": "/home/u"})
    assert [str(p) for p in paths] == ["/home/u/.claude/.credentials.json"]


def test_claude_adapter_registers_credential_path_on_macos() -> None:
    paths = ClaudeAdapter().credential_artifact_paths("Darwin", {"HOME": "/Users/u"})
    assert [str(p) for p in paths] == ["/Users/u/.claude/.credentials.json"]


def test_claude_adapter_credential_path_needs_home() -> None:
    assert ClaudeAdapter().credential_artifact_paths("Linux", {}) == []


def test_other_adapter_registers_no_credential_path() -> None:
    # The default seam returns nothing rather than guessing a location.
    assert CursorAdapter().credential_artifact_paths("Linux", {"HOME": "/home/u"}) == []
