# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Serialize a Snapshot to a baseline file, and load one back with an integrity check.

The baseline is byte-stable JSON: the same posture always writes the same bytes
(``created_at`` metadata aside), so it diffs cleanly in version control. On load,
the stored digest is recomputed from the facts — a mismatch means the file was
edited or corrupted, and the caller can refuse to trust it.

**Two different guarantees, and the difference matters.** The digest detects
*accident*: truncation, a bad merge, a partial write. It cannot detect a
motivated editor, because it is a plain hash of the facts — anyone who can
rewrite the file can recompute it, and no key is involved. That is a real gap
wherever the baseline is the control: drift is the mechanism that catches a slow
compromise, so "no drift" is only worth what the baseline is worth, and a
baseline lives in a repository that many people can push to.

:func:`load_verified_baseline` closes it, opt-in: a detached signature over the
baseline bytes, verified before the file is parsed, reusing the same machinery as
the LAN manifest and the data-pack (:mod:`mcpscan.lan.verify`) under a dedicated
``mcpscan-baseline`` namespace so a signature minted for one channel can never
verify in another. As in those channels the tool only *verifies* — signing is the
operator's action with their own key, and no private key is ever handled here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from .model import DRIFT_SCHEMA_VERSION, FactKind, PostureFact, Snapshot
from .snapshot import snapshot_digest

if TYPE_CHECKING:  # imported lazily at runtime so a plain diff never loads lan/verify
    from ..lan.verify import Verifier

# Domain separation, mirroring the data-pack channel: an SSHSIG carries its
# namespace, so ``ssh`` gets a distinct one …
BASELINE_SSH_NAMESPACE = "mcpscan-baseline"
# … while a raw Ed25519 signature carries nothing, so the context is prefixed to
# the signed bytes instead. Signers must sign ``BASELINE_ED25519_CONTEXT + bytes``.
BASELINE_ED25519_CONTEXT = b"mcpscan-baseline\x00"


class BaselineError(Exception):
    """A baseline file that could not be parsed or failed its integrity check."""


def snapshot_to_dict(snapshot: Snapshot, *, created_at: str | None = None) -> dict[str, object]:
    """A JSON-serializable baseline dict. ``created_at`` is metadata (not hashed)."""
    return {
        "tool": "ianua-broker",
        "schema_version": snapshot.schema_version,
        "created_at": created_at,
        "digest": snapshot_digest(snapshot),
        "facts": [
            {
                "kind": f.kind.value,
                "key": f.key,
                "summary": f.summary,
                "detail": dict(f.detail),
            }
            for f in snapshot.facts
        ],
    }


def render_baseline(snapshot: Snapshot, *, created_at: str | None = None) -> str:
    """Render a baseline as deterministic, byte-stable JSON text."""
    return (
        json.dumps(snapshot_to_dict(snapshot, created_at=created_at), indent=2, sort_keys=True)
        + "\n"
    )


def baseline_created_at(text: str) -> str | None:
    """The baseline's ``created_at`` metadata string, or ``None`` if unreadable.

    Deliberately tolerant: ``created_at`` is advisory metadata (not covered by
    the integrity digest), so a missing, null, or non-string field — or even
    malformed JSON — degrades to ``None`` ("unknown age") rather than an error.
    Integrity and shape validation stay :func:`load_baseline`'s job.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        # RecursionError (deeply-nested JSON) joins the tolerated set: this
        # helper's whole contract is "unknown age rather than an error".
        return None
    if not isinstance(data, dict):
        return None
    created = data.get("created_at")
    return created if isinstance(created, str) else None


def load_baseline(text: str, *, verify_digest: bool = True) -> Snapshot:
    """Parse a baseline file back into a Snapshot, verifying its integrity digest.

    Raises:
        BaselineError: if the JSON is malformed, the schema is unknown, or the
            recomputed digest does not match the stored one.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise BaselineError(f"malformed baseline JSON: {exc}") from exc
    except RecursionError as exc:
        # A deeply-nested baseline overflows the decoder's recursion.
        # RecursionError is a RuntimeError, so without this guard a tampered
        # baseline escapes as an uncaught crash instead of the typed refusal
        # every caller already handles.
        raise BaselineError("malformed baseline JSON: nesting is too deep") from exc
    if not isinstance(data, dict):
        raise BaselineError("baseline is not a JSON object")

    schema = data.get("schema_version")
    if schema != DRIFT_SCHEMA_VERSION:
        raise BaselineError(f"unsupported baseline schema_version {schema!r}")

    raw_facts = data.get("facts")
    if not isinstance(raw_facts, list):
        raise BaselineError("baseline 'facts' is not a list")

    facts: list[PostureFact] = []
    for item in raw_facts:
        facts.append(_fact_from_dict(item))
    snapshot = Snapshot(schema_version=DRIFT_SCHEMA_VERSION, facts=tuple(facts))

    if verify_digest:
        stored = data.get("digest")
        actual = snapshot_digest(snapshot)
        if stored != actual:
            raise BaselineError(
                "baseline integrity check failed: digest mismatch "
                "(the file was edited or corrupted)"
            )
    return snapshot


def _default_baseline_verifier(scheme: str) -> Verifier:
    """The real verifier for ``scheme``, bound to the baseline domain."""
    from ..lan.verify import VerifyResult, verify_ed25519, verify_ssh

    if scheme == "ed25519":

        def _ed(mb: bytes, sig: Path, signers: Path, operator: str) -> VerifyResult:
            return verify_ed25519(BASELINE_ED25519_CONTEXT + mb, sig, signers, operator)

        return _ed

    def _ssh(mb: bytes, sig: Path, signers: Path, operator: str) -> VerifyResult:
        return verify_ssh(mb, sig, signers, operator, namespace=BASELINE_SSH_NAMESPACE)

    return _ssh


def load_verified_baseline(
    baseline_bytes: bytes,
    signature_path: Path,
    allowed_signers: Path,
    *,
    operator: str,
    scheme: str = "ssh",
    verifier: Verifier | None = None,
) -> Snapshot:
    """Verify a detached signature over the baseline bytes, then parse them.

    Verify-or-refuse, and in that order: nothing is parsed until the signature
    over the **exact bytes on disk** verifies, so a baseline that fails is never
    partially trusted. The caller passes the bytes it already read, so the bytes
    verified are the bytes used — no second read a concurrent write could
    diverge from.

    This is strictly stronger than the digest, and it subsumes it: a signed
    baseline still has its digest checked by :func:`load_baseline` afterwards, so
    accidental corruption and deliberate rewriting are both caught, by the
    mechanism suited to each.

    Args:
        baseline_bytes: The baseline file's exact bytes.
        signature_path: Detached signature over those bytes.
        allowed_signers: The principals permitted to sign a baseline.
        operator: Which of those principals to require.
        scheme: ``ssh`` (default, dependency-free) or ``ed25519``.
        verifier: Injectable for tests, so nothing shells out.

    Raises:
        BaselineError: If the scheme is unknown, the signature does not verify,
            the bytes are not UTF-8, or the parsed baseline is malformed. Callers
            already handle this one type, so a signature failure needs no new
            error path.
    """
    if scheme not in ("ssh", "ed25519"):
        raise BaselineError(f"unsupported signature scheme {scheme!r}")

    verify = verifier or _default_baseline_verifier(scheme)
    result = verify(baseline_bytes, signature_path, allowed_signers, operator)
    if not result.ok:
        raise BaselineError(f"baseline signature refused: {result.detail}")

    try:
        text = baseline_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BaselineError(f"baseline is not valid UTF-8: {exc}") from exc
    return load_baseline(text)


def _fact_from_dict(item: object) -> PostureFact:
    if not isinstance(item, dict):
        raise BaselineError("a baseline fact is not an object")
    try:
        kind = FactKind(item["kind"])
        key = str(item["key"])
        summary = str(item["summary"])
        detail_obj = item.get("detail", {})
    except (KeyError, ValueError) as exc:
        raise BaselineError(f"invalid baseline fact: {exc}") from exc
    if not isinstance(detail_obj, dict):
        raise BaselineError("a baseline fact 'detail' is not an object")
    detail = tuple(sorted((str(k), str(v)) for k, v in detail_obj.items()))
    return PostureFact(kind=kind, key=key, summary=summary, detail=detail)
