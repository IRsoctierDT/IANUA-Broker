# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Signed data-pack refresh channel (Wave 3 Feature D).

Detection catalogs — provider secret patterns, the secret-name regex, the entropy
threshold, the agent/MCP process markers, and the credential-store path templates
— are the parts of the scanner that go stale fastest as new providers and hosts
appear. This module externalizes them into a :class:`DataPack` so they can be
refreshed *between* code releases, without shipping a new binary.

The refresh channel is opt-in and **verify-or-refuse**, following the tool's
offline-by-default identity:

- :func:`builtin_datapack` is the DEFAULT pack whose values are byte-for-byte
  today's hardcoded constants; ``checks.secrets`` and ``discovery.process_env``
  derive their catalogs from it, so a scan with no installed pack behaves exactly
  as before.
- :func:`load_verified_datapack` verifies a detached signature over the pack
  bytes (reusing the LAN signature machinery in :mod:`mcpscan.lan.verify`, under
  a dedicated ``mcpscan-datapack`` namespace) before parsing. An unverified,
  invalid, or malformed pack is **refused** — returned as a
  :class:`DataPackError` — and the caller falls back to the built-in pack. It is
  never silently used.
- ``mcpscan update-datapack`` performs that verification once and installs the
  pack into a local store; :func:`load_local_datapack` loads the installed pack
  on later scans (structural validation only — the signature was checked at
  install time and the store is owner-only, trusted at rest like any of the
  user's own config).

No network is ever contacted here: verification is a local ``ssh-keygen`` /
``ed25519`` check over a local file. The verifier is injectable so tests never
shell out.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # imported lazily at runtime so a plain scan never loads lan/verify
    from .lan.verify import Verifier, VerifyResult

DATAPACK_SCHEMA_VERSION = "1.0"

# The ssh-signature namespace for this channel, distinct from the LAN manifest's
# ``mcpscan-lan`` so a signature minted for one context can never verify in the
# other (domain separation).
DATAPACK_SSH_NAMESPACE = "mcpscan-datapack"

# Raw Ed25519 signatures (unlike SSHSIG) carry no namespace field, so the datapack
# ed25519 path binds the domain itself: the signer signs this context prefix
# concatenated with the pack bytes. Without it, a LAN ed25519 signature over the
# same bytes would cross-verify here. Signers must sign ``DATAPACK_ED25519_CONTEXT
# + pack_bytes``.
DATAPACK_ED25519_CONTEXT = b"mcpscan-datapack\x00"

# --- built-in catalogs (the single source of truth; formerly hardcoded in the
#     checks). Values here are byte-identical to the previous inline constants. --
_BUILTIN_PROVIDER_PATTERNS: tuple[tuple[str, str], ...] = (
    ("Anthropic API key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("OpenAI API key", r"sk-[A-Za-z0-9]{20,}"),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("GitHub fine-grained PAT", r"github_pat_[A-Za-z0-9_]{50,}"),
    ("AWS access key id", r"AKIA[0-9A-Z]{16}"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{35}"),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("Private key", r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
)
_BUILTIN_SECRET_NAME = (  # nosec B105 (regex over secret-bearing key NAMES, not a secret value)
    r"(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|ACCESS[_-]?KEY|PRIVATE[_-]?KEY)"
)
_BUILTIN_ENTROPY_THRESHOLD = 3.5
_BUILTIN_MIN_ENTROPY_LEN = 20
_BUILTIN_AGENT_MARKERS: tuple[str, ...] = (
    "mcp",
    "modelcontextprotocol",
    "model-context-protocol",
    "claude",
    "cursor",
    "windsurf",
    "cline",
    "continue",
    "zed",
)
# Credential-store path templates (the surface the token-store registry names).
# Carried and validated by the pack so the datapack is the single catalog home;
# path *resolution* stays OS-specific in adapters.paths, so this catalog is
# reference data rather than a live check input in this wave.
_BUILTIN_TOKEN_STORE_TEMPLATES: tuple[str, ...] = ("~/.claude/.credentials.json",)


@dataclass(frozen=True)
class DataPack:
    """The externalizable detection catalogs, in serializable (source) form.

    Regexes are held as their **source strings** so the pack round-trips through
    JSON; :func:`compile_secret_catalog` / :func:`compile_agent_catalog` turn them
    into the compiled forms the checks use.
    """

    schema_version: str
    provider_patterns: tuple[tuple[str, str], ...]  # (label, regex source)
    secret_name_pattern: str  # regex source (matched case-insensitively)
    entropy_threshold: float
    min_entropy_len: int
    agent_markers: tuple[str, ...]
    token_store_templates: tuple[str, ...]


@dataclass(frozen=True)
class DataPackError:
    """A pack that could not be verified, parsed, or validated (fail-closed)."""

    message: str


@dataclass(frozen=True)
class SecretCatalog:
    """The compiled secret-detection catalog a secrets check operates on."""

    provider_patterns: tuple[tuple[str, re.Pattern[str]], ...]
    secret_name: re.Pattern[str]
    entropy_threshold: float
    min_entropy_len: int


@dataclass(frozen=True)
class AgentCatalog:
    """The compiled agent/MCP process-marker catalog for the scope guardrail."""

    marker_re: re.Pattern[str]


def compile_secret_catalog(pack: DataPack) -> SecretCatalog:
    """Compile a pack's secret patterns into the form the secrets checks use."""
    return SecretCatalog(
        provider_patterns=tuple(
            (label, re.compile(source)) for label, source in pack.provider_patterns
        ),
        secret_name=re.compile(pack.secret_name_pattern, re.IGNORECASE),
        entropy_threshold=pack.entropy_threshold,
        min_entropy_len=pack.min_entropy_len,
    )


def compile_agent_catalog(pack: DataPack) -> AgentCatalog:
    """Compile a pack's agent markers into the word-boundary matcher.

    Reproduces exactly the previous inline construction: each marker is matched
    only at word boundaries (so a short marker never fires on a coincidental
    substring) and case-insensitively. An empty marker set compiles to a matcher
    that never matches, rather than the empty alternation ``\\b(?:)\\b`` (which
    would match at every boundary).
    """
    markers = pack.agent_markers
    if not markers:
        return AgentCatalog(marker_re=re.compile(r"(?!)"))
    marker_re = re.compile(
        r"\b(?:" + "|".join(re.escape(m) for m in markers) + r")\b",
        re.IGNORECASE,
    )
    return AgentCatalog(marker_re=marker_re)


def builtin_datapack() -> DataPack:
    """The default pack — today's hardcoded catalogs, in one place."""
    return DataPack(
        schema_version=DATAPACK_SCHEMA_VERSION,
        provider_patterns=_BUILTIN_PROVIDER_PATTERNS,
        secret_name_pattern=_BUILTIN_SECRET_NAME,
        entropy_threshold=_BUILTIN_ENTROPY_THRESHOLD,
        min_entropy_len=_BUILTIN_MIN_ENTROPY_LEN,
        agent_markers=_BUILTIN_AGENT_MARKERS,
        token_store_templates=_BUILTIN_TOKEN_STORE_TEMPLATES,
    )


# Compiled once: the default catalogs the pure checks fall back to when no pack
# is threaded in (keeps every existing call site and test byte-identical).
_BUILTIN_SECRET_CATALOG = compile_secret_catalog(builtin_datapack())
_BUILTIN_AGENT_CATALOG = compile_agent_catalog(builtin_datapack())


def builtin_secret_catalog() -> SecretCatalog:
    """The default (built-in) compiled secret catalog — a shared singleton."""
    return _BUILTIN_SECRET_CATALOG


def builtin_agent_catalog() -> AgentCatalog:
    """The default (built-in) compiled agent catalog — a shared singleton."""
    return _BUILTIN_AGENT_CATALOG


def _err_str(data: object, key: str) -> str | DataPackError:
    value = data.get(key) if isinstance(data, dict) else None
    if not isinstance(value, str) or not value.strip():
        return DataPackError(f"datapack field {key!r} must be a non-empty string")
    return value


def _err_number(data: dict[str, object], key: str) -> float | DataPackError:
    value = data.get(key)
    # bool is an int subclass — reject it so a JSON ``true`` is not read as 1.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return DataPackError(f"datapack field {key!r} must be a number")
    if value < 0:
        return DataPackError(f"datapack field {key!r} must be non-negative")
    return float(value)


def _err_int(data: dict[str, object], key: str) -> int | DataPackError:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return DataPackError(f"datapack field {key!r} must be an integer")
    if value < 1:
        return DataPackError(f"datapack field {key!r} must be >= 1")
    return value


def _err_str_list(
    data: dict[str, object], key: str, *, allow_empty: bool
) -> tuple[str, ...] | DataPackError:
    value = data.get(key)
    if not isinstance(value, list):
        return DataPackError(f"datapack field {key!r} must be an array")
    if not allow_empty and not value:
        return DataPackError(f"datapack field {key!r} must be a non-empty array")
    if not all(isinstance(item, str) and item for item in value):
        return DataPackError(f"every entry in {key!r} must be a non-empty string")
    return tuple(str(item) for item in value)


def _parse_provider_patterns(value: object) -> tuple[tuple[str, str], ...] | DataPackError:
    if not isinstance(value, list):
        return DataPackError("datapack field 'provider_patterns' must be an array")
    patterns: list[tuple[str, str]] = []
    for entry in value:
        if not isinstance(entry, dict):
            return DataPackError("every 'provider_patterns' entry must be an object")
        label = entry.get("label")
        source = entry.get("pattern")
        if not isinstance(label, str) or not label.strip():
            return DataPackError("a provider pattern is missing a non-empty 'label'")
        if not isinstance(source, str) or not source:
            return DataPackError(f"provider pattern {label!r} is missing a 'pattern' string")
        compiled = _safe_compile(source)
        if isinstance(compiled, DataPackError):
            return DataPackError(f"provider pattern {label!r}: {compiled.message}")
        patterns.append((label, source))
    return tuple(patterns)


def _safe_compile(source: str) -> re.Pattern[str] | DataPackError:
    try:
        return re.compile(source)
    except re.error as exc:
        return DataPackError(f"invalid regex {source!r}: {exc}")


def parse_datapack(raw: str) -> DataPack | DataPackError:
    """Parse and validate datapack JSON into a :class:`DataPack` or error.

    Never raises: malformed JSON, a wrong shape, an out-of-range value, or an
    uncompilable regex all return a :class:`DataPackError`.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        return DataPackError(f"invalid datapack JSON: {exc}")
    if not isinstance(data, dict):
        return DataPackError("datapack must be a JSON object")

    schema_version = _err_str(data, "schema_version")
    if isinstance(schema_version, DataPackError):
        return schema_version

    provider_patterns = _parse_provider_patterns(data.get("provider_patterns"))
    if isinstance(provider_patterns, DataPackError):
        return provider_patterns

    secret_name = _err_str(data, "secret_name_pattern")
    if isinstance(secret_name, DataPackError):
        return secret_name
    compiled_name = _safe_compile(secret_name)
    if isinstance(compiled_name, DataPackError):
        return DataPackError(f"secret_name_pattern: {compiled_name.message}")

    entropy_threshold = _err_number(data, "entropy_threshold")
    if isinstance(entropy_threshold, DataPackError):
        return entropy_threshold

    min_entropy_len = _err_int(data, "min_entropy_len")
    if isinstance(min_entropy_len, DataPackError):
        return min_entropy_len

    agent_markers = _err_str_list(data, "agent_markers", allow_empty=False)
    if isinstance(agent_markers, DataPackError):
        return agent_markers

    token_store_templates = _err_str_list(data, "token_store_templates", allow_empty=True)
    if isinstance(token_store_templates, DataPackError):
        return token_store_templates

    return DataPack(
        schema_version=schema_version,
        provider_patterns=provider_patterns,
        secret_name_pattern=secret_name,
        entropy_threshold=entropy_threshold,
        min_entropy_len=min_entropy_len,
        agent_markers=agent_markers,
        token_store_templates=token_store_templates,
    )


def datapack_to_json(pack: DataPack) -> str:
    """Serialize a pack to canonical JSON (round-trips through :func:`parse_datapack`)."""
    payload = {
        "schema_version": pack.schema_version,
        "provider_patterns": [
            {"label": label, "pattern": source} for label, source in pack.provider_patterns
        ],
        "secret_name_pattern": pack.secret_name_pattern,
        "entropy_threshold": pack.entropy_threshold,
        "min_entropy_len": pack.min_entropy_len,
        "agent_markers": list(pack.agent_markers),
        "token_store_templates": list(pack.token_store_templates),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def first_allowed_signer(text: str) -> str | None:
    """Return the first principal named in an allowed-signers file, or ``None``.

    Both the OpenSSH allowed-signers format and this channel's ed25519 format put
    the signer principal first on each line; the CLI uses this to default the
    signer identity when ``--signer`` is not given.
    """
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts:
            return parts[0]
    return None


def _default_datapack_verifier(scheme: str) -> Verifier:
    """The real verifier for ``scheme`` (ssh under the datapack namespace, or ed25519)."""
    from .lan.verify import verify_ed25519, verify_ssh

    if scheme == "ed25519":

        def _ed(mb: bytes, sig: Path, signers: Path, operator: str) -> VerifyResult:
            # Domain-separate from the LAN ed25519 channel (raw signatures have no
            # namespace field): verify over the datapack context + the pack bytes.
            return verify_ed25519(DATAPACK_ED25519_CONTEXT + mb, sig, signers, operator)

        return _ed

    def _ssh(mb: bytes, sig: Path, signers: Path, operator: str) -> VerifyResult:
        return verify_ssh(mb, sig, signers, operator, namespace=DATAPACK_SSH_NAMESPACE)

    return _ssh


def load_verified_datapack(
    pack_path: Path,
    signature_path: Path,
    allowed_signers: Path,
    *,
    operator: str,
    scheme: str = "ssh",
    verifier: Verifier | None = None,
    pack_bytes: bytes | None = None,
) -> DataPack | DataPackError:
    """Verify a detached signature over a pack file, then parse it.

    The signature binds to the exact pack bytes (as the LAN manifest does). On a
    failed signature the pack is **refused** — a :class:`DataPackError` naming the
    reason is returned and nothing is parsed. ``verifier`` is injectable so tests
    never shell out; when omitted the real ssh/ed25519 verifier is used.

    Pass ``pack_bytes`` to verify content the caller already holds (read once),
    so the bytes that are verified are exactly the bytes the caller goes on to
    install — no second read that a concurrent write could diverge from.
    """
    if scheme not in ("ssh", "ed25519"):
        return DataPackError(f"unsupported signature scheme {scheme!r}")
    if pack_bytes is None:
        try:
            pack_bytes = pack_path.read_bytes()
        except OSError as exc:
            return DataPackError(f"cannot read datapack {pack_path}: {exc}")

    verify = verifier or _default_datapack_verifier(scheme)
    result = verify(pack_bytes, signature_path, allowed_signers, operator)
    if not result.ok:
        return DataPackError(f"datapack signature refused: {result.detail}")

    try:
        raw = pack_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        return DataPackError(f"datapack is not valid UTF-8: {exc}")
    return parse_datapack(raw)


def load_local_datapack(store_path: Path) -> DataPack | None:
    """Load the installed store pack, or ``None`` to fall back to the built-in.

    Structural validation only: the signature was verified at install time by
    ``update-datapack`` and the store is owner-only, so it is trusted at rest like
    any of the user's own config. A missing store, an unreadable file, or content
    that no longer parses all return ``None`` (fall back to the built-in pack) —
    a corrupt store can never crash a scan.
    """
    try:
        raw = store_path.read_text(encoding="utf-8")
    except OSError:
        return None
    parsed = parse_datapack(raw)
    if isinstance(parsed, DataPackError):
        return None
    return parsed
