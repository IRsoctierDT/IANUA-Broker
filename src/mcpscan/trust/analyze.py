# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Compute trust profiles from parsed configs (VISION Tier 4).

Each MCP server is scored across four trust factors using the **same public
predicates the scanner already trusts** (dangerous/wildcard tool detection,
secret detection, floating-runner detection) — so trust analysis never diverges
from what ``scan`` would flag. It then derives :class:`RiskRelationship`s from
factor *combinations*, which is the part ``scan`` does not do.

Pure over its inputs: ``analyze_config`` takes a parsed config and returns
profiles with no I/O. Risk points are capped per factor so no single dimension
can dominate the 0–100 Trust Score. One relationship is cross-subject:
``SHARED-CREDENTIAL`` joins credential fingerprints across every profiled
subject (``apply_shared_credentials``), because a shared secret's blast radius
is invisible to any single profile.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace

from ..adapters.base import ParsedConfig, ServerDecl
from ..checks.pinning import check_server_pinning
from ..checks.secrets import check_server_env
from ..checks.tool_scope import has_broad_wildcard, is_dangerous_tool
from ..discovery.sockets import ReachTier, classify_reachability
from ..domain import SecretFingerprint
from ..scoring import grade_for_score, worst_grade
from .model import (
    TRUST_SCHEMA_VERSION,
    FactorScore,
    RiskRelationship,
    TrustFactor,
    TrustProfile,
    TrustReport,
)

# Per-factor risk ceilings (points off the 100 Trust Score).
_SECRET_BASE, _SECRET_PER_EXTRA, _SECRET_CAP = 25, 5, 40
_DANGEROUS_TOOL, _WILDCARD_TOOL, _PRIVILEGE_CAP = 25, 20, 40
_AUTONOMY = 15
_PROVENANCE = 10
# Network reach (a NEW dimension — does not overlap the four above, so points add
# cleanly). Wildcard/public reach is the report's post-compromise story, so it
# outweighs a private-LAN-only bind.
_REACH_WIDE, _REACH_LAN = 20, 10

# Argument flags and arg/env keys that name a bind address, plus the wildcard
# tokens that are a bind hint on their own. Deliberately small to keep false
# positives near zero: a trust profile scores DECLARED config, so reach is
# inferred only from an explicit host/bind hint in the server's own args/env.
_BIND_FLAGS = frozenset({"--host", "--bind", "--address"})
_BIND_KEYS = frozenset({"HOST", "BIND", "BIND_ADDRESS", "ADDRESS"})
_WILDCARD_TOKENS = frozenset({"0.0.0.0", "::"})  # nosec B104 (detecting, not binding)

# Ordering of reach tiers by how exposed they are (higher = more reachable), so
# ``bind_hint`` can keep the most-exposed hint when several are present.
_REACH_RANK: dict[ReachTier, int] = {
    ReachTier.LOOPBACK: 0,
    ReachTier.PRIVATE_LAN: 1,
    ReachTier.PUBLIC_ROUTABLE: 2,
    ReachTier.WILDCARD: 3,
}


def _secret_factor(server: ServerDecl, path: str) -> FactorScore:
    n = len(check_server_env(server, path))
    if n == 0:
        return FactorScore(TrustFactor.SECRET_ACCESS, 0, "no credentials in its environment")
    risk = min(_SECRET_BASE + (n - 1) * _SECRET_PER_EXTRA, _SECRET_CAP)
    plural = "credential" if n == 1 else "credentials"
    return FactorScore(TrustFactor.SECRET_ACCESS, risk, f"holds {n} {plural} in its environment")


def _privilege_factor(server: ServerDecl) -> FactorScore:
    dangerous = [t for t in server.auto_approve if is_dangerous_tool(t)]
    wildcard = [t for t in server.auto_approve if has_broad_wildcard(t)]
    risk = 0
    if dangerous:
        risk += _DANGEROUS_TOOL
    if wildcard:
        risk += _WILDCARD_TOOL
    risk = min(risk, _PRIVILEGE_CAP)
    if risk == 0:
        return FactorScore(TrustFactor.TOOL_PRIVILEGE, 0, "no dangerous or wildcard tool grants")
    parts = []
    if dangerous:
        parts.append(f"{len(dangerous)} dangerous tool(s)")
    if wildcard:
        parts.append(f"{len(wildcard)} wildcard grant(s)")
    return FactorScore(TrustFactor.TOOL_PRIVILEGE, risk, "auto-approves " + " and ".join(parts))


def _autonomy_factor(server: ServerDecl) -> FactorScore:
    if not server.auto_approve:
        return FactorScore(TrustFactor.AUTONOMY, 0, "every tool call needs approval")
    n = len(server.auto_approve)
    return FactorScore(
        TrustFactor.AUTONOMY, _AUTONOMY, f"auto-approves {n} tool(s) with no human in the loop"
    )


def _provenance_factor(server: ServerDecl, path: str) -> FactorScore:
    if check_server_pinning(server, path):
        return FactorScore(
            TrustFactor.CODE_PROVENANCE, _PROVENANCE, "runs an unpinned / remotely-fetched package"
        )
    return FactorScore(TrustFactor.CODE_PROVENANCE, 0, "runs a pinned or local command")


def _bind_candidates(server: ServerDecl) -> list[str]:
    """Collect the address values hinted by the server's args and env (pure)."""
    values: list[str] = []
    args = server.args
    i, n = 0, len(args)
    while i < n:
        arg = args[i]
        key, sep, inline = arg.partition("=")
        if sep and (key in _BIND_FLAGS or key.upper() in _BIND_KEYS):  # --host=0.0.0.0 / HOST=…
            values.append(inline)
        elif arg in _BIND_FLAGS and i + 1 < n:  # --host 0.0.0.0
            values.append(args[i + 1])
            i += 1
        elif arg in _WILDCARD_TOKENS:  # a bare wildcard token is a hint on its own
            values.append(arg)
        i += 1
    for env_key, value in server.env:
        if env_key.upper() in _BIND_KEYS:
            values.append(value)
    return values


def bind_hint(server: ServerDecl) -> ReachTier | None:
    """Infer a network-reach tier from bind hints in a server's args/env.

    Pure, no sockets: a trust profile scores a DECLARED server, so its reach is
    read from an explicit ``--host``/``--bind``/``--address`` value, a
    ``HOST``/``BIND_ADDRESS`` arg or env value, or a literal ``0.0.0.0``/``::``
    token. Returns the most-exposed non-loopback tier hinted, or ``None`` when no
    bind hint is present or every hint is loopback-only.
    """
    best: ReachTier | None = None
    for value in _bind_candidates(server):
        tier = classify_reachability(value)
        if tier is ReachTier.LOOPBACK:
            continue
        if best is None or _REACH_RANK[tier] > _REACH_RANK[best]:
            best = tier
    return best


def _reach_factor(server: ServerDecl) -> FactorScore:
    tier = bind_hint(server)
    if tier is None:
        return FactorScore(TrustFactor.EXPOSURE_REACH, 0, "no network-reachable bind hint")
    if tier is ReachTier.PRIVATE_LAN:
        return FactorScore(
            TrustFactor.EXPOSURE_REACH,
            _REACH_LAN,
            "binds to a private-LAN address (reachable on the local network)",
        )
    return FactorScore(
        TrustFactor.EXPOSURE_REACH,
        _REACH_WIDE,
        "binds to a wildcard / public address (reachable from any network)",
    )


# --- risk relationships: dangerous *combinations* of factors ----------------
def _relationships(active: set[TrustFactor]) -> list[RiskRelationship]:
    rels: list[RiskRelationship] = []
    F = TrustFactor
    # Headline composite: autonomy + tool-privilege + secret-access all active on
    # ONE subject is the full autonomous-exfiltration path — the tool can read the
    # secrets, wields dangerous/wildcard tools to act on them, AND auto-approves,
    # so it exfiltrates with no human in the loop (the mechanism behind the report's
    # worst-prevented vector, data exfiltration). Emitted FIRST so the triple reads
    # as the headline above the pair relationships it subsumes — those still fire
    # below because each names a different facet of the same subject.
    #
    # Relationship ONLY — no score/grade/factor-risk change: all three factors are
    # already billed individually, so adding points here would double-bill the same
    # evidence (same stance as SHARED-CREDENTIAL). This exfil path (autonomy ×
    # privilege × secret) and the EXPOSED-PRIVILEGED relationship below (reach ×
    # privilege) name DIFFERENT factor sets — outbound autonomous egress vs inbound
    # network reach — so they do not double-signal the same condition.
    if F.AUTONOMY in active and F.TOOL_PRIVILEGE in active and F.SECRET_ACCESS in active:
        rels.append(
            RiskRelationship(
                id="AUTONOMOUS-EXFIL-PATH",
                title="Autonomous exfiltration path",
                rationale=(
                    "This tool holds credentials, wields dangerous/wildcard tools, AND "
                    "auto-approves — so it can read secrets and act on them with no human "
                    "in the loop, the mechanism behind the report's worst-prevented vector "
                    "(data exfiltration)."
                ),
                factors=(F.AUTONOMY, F.TOOL_PRIVILEGE, F.SECRET_ACCESS),
            )
        )
    if F.SECRET_ACCESS in active and F.TOOL_PRIVILEGE in active:
        rels.append(
            RiskRelationship(
                id="PRIVILEGED-SECRET-HOLDER",
                title="Privileged secret holder",
                rationale=(
                    "This tool both holds credentials and wields dangerous/wildcard tools — "
                    "a single compromise leaks the secrets and the power to use them."
                ),
                factors=(F.SECRET_ACCESS, F.TOOL_PRIVILEGE),
            )
        )
    if F.AUTONOMY in active and F.TOOL_PRIVILEGE in active:
        rels.append(
            RiskRelationship(
                id="AUTONOMOUS-PRIVILEGED",
                title="Autonomous privileged tool",
                rationale=(
                    "Dangerous/wildcard tools are auto-approved, so they run with no human "
                    "in the loop — the agent can take powerful actions unsupervised."
                ),
                factors=(F.AUTONOMY, F.TOOL_PRIVILEGE),
            )
        )
    if F.AUTONOMY in active and F.SECRET_ACCESS in active:
        rels.append(
            RiskRelationship(
                id="AUTONOMOUS-SECRET-HOLDER",
                title="Autonomous secret holder",
                rationale=(
                    "The tool auto-approves actions while holding credentials, so those "
                    "credentials can be used without a human approving each call."
                ),
                factors=(F.AUTONOMY, F.SECRET_ACCESS),
            )
        )
    if F.CODE_PROVENANCE in active and F.TOOL_PRIVILEGE in active:
        rels.append(
            RiskRelationship(
                id="UNVETTED-PRIVILEGED",
                title="Unvetted privileged code",
                rationale=(
                    "Unpinned, remotely-fetched code is granted dangerous/wildcard tools — "
                    "a supply-chain change could exercise them on the next run."
                ),
                factors=(F.CODE_PROVENANCE, F.TOOL_PRIVILEGE),
            )
        )
    # Reach × privilege: a network-reachable server that also wields
    # dangerous/wildcard tools gives an on-network attacker remote reach into
    # powerful actions — the report's post-compromise story. Relationship only
    # (both factors already billed); a different factor set from the exfil path
    # above, so no double-counting.
    if F.EXPOSURE_REACH in active and F.TOOL_PRIVILEGE in active:
        rels.append(
            RiskRelationship(
                id="EXPOSED-PRIVILEGED",
                title="Network-reachable privileged tool",
                rationale=(
                    "A network-reachable server also wields dangerous/wildcard tools — "
                    "remote reach into powerful actions."
                ),
                factors=(F.EXPOSURE_REACH, F.TOOL_PRIVILEGE),
            )
        )
    return rels


def profile_server(server: ServerDecl, path: str, host: str) -> TrustProfile:
    """Score one MCP server across the trust factors and derive its relationships."""
    factors = (
        _secret_factor(server, path),
        _privilege_factor(server),
        _autonomy_factor(server),
        _provenance_factor(server, path),
        _reach_factor(server),
    )
    total_risk = sum(f.risk for f in factors)
    score = max(0, 100 - total_risk)
    active = {f.factor for f in factors if f.present}
    return TrustProfile(
        subject=f"{path}#{server.name}",
        server_name=server.name,
        host=host,
        location=path,
        score=score,
        grade=grade_for_score(score),
        factors=factors,
        relationships=tuple(_relationships(active)),
    )


def analyze_config(config: ParsedConfig, host: str) -> list[TrustProfile]:
    """Trust-profile every server declared in one parsed config."""
    return [profile_server(server, config.path, host) for server in config.servers]


def config_credential_fingerprints(
    config: ParsedConfig,
) -> dict[str, tuple[SecretFingerprint, ...]]:
    """Map each secret-holding subject id to its detected credential fingerprints.

    Reuses the scanner's own secret predicate (``check_server_env``), whose
    findings already reduce every detected env value to a
    :class:`~mcpscan.domain.SecretFingerprint` via ``redaction.fingerprint_secret``
    — so no raw secret value is ever stored or returned here. Pure, no I/O.
    """
    out: dict[str, tuple[SecretFingerprint, ...]] = {}
    for server in config.servers:
        fingerprints = tuple(
            f.secret for f in check_server_env(server, config.path) if f.secret is not None
        )
        if fingerprints:
            out[f"{config.path}#{server.name}"] = fingerprints
    return out


def apply_shared_credentials(
    profiles: Sequence[TrustProfile],
    fingerprints: Mapping[str, Sequence[SecretFingerprint]],
) -> list[TrustProfile]:
    """Add a ``SHARED-CREDENTIAL`` relationship where one secret spans >= 2 subjects.

    Join key is ``(sha256_8, length)`` per fingerprint. Relationship **only**:
    scores, grades, and factor risks are untouched, because the secret itself is
    already billed by the SECRET_ACCESS factor — adding points here would
    double-bill the same evidence.

    Collision caveat (same stance as :class:`~mcpscan.domain.SecretFingerprint`):
    ``sha256_8`` is a 32-bit truncation, so a false pairing between two distinct
    secrets is possible — the relationship is a triage signal, not proof.

    Pure and deterministic over its inputs; profiles are frozen, so involved
    ones are rebuilt with :func:`dataclasses.replace`.
    """
    holders: dict[tuple[str, int], set[str]] = {}
    for subject, fps in fingerprints.items():
        for fp in fps:
            holders.setdefault((fp.sha256_8, fp.length), set()).add(subject)

    peers: dict[str, set[str]] = {}
    for subjects in holders.values():
        if len(subjects) < 2:
            continue
        for subject in subjects:
            peers.setdefault(subject, set()).update(subjects - {subject})

    if not peers:
        return list(profiles)

    updated: list[TrustProfile] = []
    for profile in profiles:
        others = peers.get(profile.subject)
        if not others:
            updated.append(profile)
            continue
        relationship = RiskRelationship(
            id="SHARED-CREDENTIAL",
            title="Shared credential blast radius",
            rationale=(
                f"Shared credential blast radius: this tool shares a credential with "
                f"{len(others)} other tool(s); compromising one exposes all."
            ),
            factors=(TrustFactor.SECRET_ACCESS,),
        )
        updated.append(replace(profile, relationships=profile.relationships + (relationship,)))
    return updated


def build_trust_report(profiles: list[TrustProfile]) -> TrustReport:
    """Assemble profiles into a report, grading overall by the worst subject."""
    ordered = sorted(profiles, key=lambda p: (p.score, p.subject))
    overall = worst_grade([p.grade for p in ordered]) if ordered else "A"
    return TrustReport(
        schema_version=TRUST_SCHEMA_VERSION, profiles=tuple(ordered), overall_grade=overall
    )
