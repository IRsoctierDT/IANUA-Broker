# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Agent trust analysis (VISION Tier 4): a Trust Score per agent tool.

``collect_trust`` discovers host configs and scores each MCP server across the
trust factors, deriving the risk *relationships* (dangerous factor combinations)
that a single hygiene check can't see. Read-only, offline, and secretless — a
profile carries a credential count, never a value.
"""

from .analyze import (
    analyze_config,
    apply_shared_credentials,
    bind_hint,
    build_trust_report,
    config_credential_fingerprints,
    profile_server,
)
from .collect import collect_trust
from .model import (
    FactorScore,
    RiskRelationship,
    TrustFactor,
    TrustProfile,
    TrustReport,
)

__all__ = [
    "FactorScore",
    "RiskRelationship",
    "TrustFactor",
    "TrustProfile",
    "TrustReport",
    "analyze_config",
    "apply_shared_credentials",
    "bind_hint",
    "build_trust_report",
    "collect_trust",
    "config_credential_fingerprints",
    "profile_server",
]
