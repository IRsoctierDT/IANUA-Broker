# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Framework mappings for scanner findings (VISION Tier 2).

Maps every check id the scanner can emit to the security frameworks an
assessment consumer speaks: **MITRE ATT&CK**, **MITRE ATLAS**, **OWASP Top 10
for LLM Applications**, **NIST AI RMF** (function level), and **CIS Controls
v8** (control level).

The table is deliberately *data*, in one place, so a human can audit every
mapping. Mapping policy — conservative by construction:

- A framework reference is included only where the technique/control match is
  direct; a check with no solid match in some framework simply has no entry
  for it (absence over invention).
- NIST AI RMF is mapped at the **function** level (GOVERN/MAP/MEASURE/MANAGE)
  and CIS at the **control** level — deeper subcategory claims would imply a
  rigor this static table can't guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Framework(Enum):
    """A security framework the atlas can cite."""

    ATTACK = "mitre_attack"
    ATLAS = "mitre_atlas"
    OWASP_LLM = "owasp_llm_top10"
    NIST_AI_RMF = "nist_ai_rmf"
    CIS = "cis_controls_v8"


_FRAMEWORK_LABELS: dict[Framework, str] = {
    Framework.ATTACK: "MITRE ATT&CK",
    Framework.ATLAS: "MITRE ATLAS",
    Framework.OWASP_LLM: "OWASP LLM Top 10",
    Framework.NIST_AI_RMF: "NIST AI RMF",
    Framework.CIS: "CIS Controls v8",
}


def framework_label(framework: Framework) -> str:
    """Human-readable framework name."""
    return _FRAMEWORK_LABELS[framework]


@dataclass(frozen=True)
class FrameworkRef:
    """One citation: a framework plus the technique/control it names."""

    framework: Framework
    ref: str  # e.g. "T1552.001", "AML.T0010", "LLM06", "MANAGE", "Control 6"
    title: str  # the framework's own name for it


# --- shared refs (one definition per citation, reused across checks) ---------
_CREDS_IN_FILES = FrameworkRef(
    Framework.ATTACK, "T1552.001", "Unsecured Credentials: Credentials In Files"
)
_ATLAS_CREDS = FrameworkRef(Framework.ATLAS, "AML.T0055", "Unsecured Credentials")
_LLM_SENSITIVE = FrameworkRef(Framework.OWASP_LLM, "LLM02", "Sensitive Information Disclosure")
_RMF_GOVERN = FrameworkRef(Framework.NIST_AI_RMF, "GOVERN", "Govern function")
_RMF_MAP = FrameworkRef(Framework.NIST_AI_RMF, "MAP", "Map function")
_RMF_MANAGE = FrameworkRef(Framework.NIST_AI_RMF, "MANAGE", "Manage function")
_CIS_DATA = FrameworkRef(Framework.CIS, "Control 3", "Data Protection")
_CIS_ACCESS = FrameworkRef(Framework.CIS, "Control 6", "Access Control Management")
_CIS_CONFIG = FrameworkRef(
    Framework.CIS, "Control 4", "Secure Configuration of Enterprise Assets and Software"
)
_CIS_APPSEC = FrameworkRef(Framework.CIS, "Control 16", "Application Software Security")

_SUPPLY_CHAIN = FrameworkRef(
    Framework.ATTACK, "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain"
)
# A known-vulnerable *dependency* named on the launch command (Wave 3 Feature V):
# the sub-technique for a compromised software dependency, not the wider supply
# chain, leads the VULN-KNOWN citation.
_SUPPLY_DEPS = FrameworkRef(
    Framework.ATTACK,
    "T1195.001",
    "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
)
_ATLAS_SUPPLY = FrameworkRef(Framework.ATLAS, "AML.T0010", "ML Supply Chain Compromise")
_LLM_SUPPLY = FrameworkRef(Framework.OWASP_LLM, "LLM03", "Supply Chain")

_PUBLIC_FACING = FrameworkRef(Framework.ATTACK, "T1190", "Exploit Public-Facing Application")
_ATLAS_PUBLIC = FrameworkRef(Framework.ATLAS, "AML.T0049", "Exploit Public-Facing Application")

_VALID_ACCOUNTS = FrameworkRef(Framework.ATTACK, "T1078", "Valid Accounts")

# Token/credential stores at rest (Wave 2 Feature H). T1552 is the Unsecured
# Credentials parent; T1528 names the theft of a stored application access token
# — the exact prize a world-readable or stale token store hands an attacker.
_UNSECURED_CREDS = FrameworkRef(Framework.ATTACK, "T1552", "Unsecured Credentials")
_STEAL_APP_TOKEN = FrameworkRef(Framework.ATTACK, "T1528", "Steal Application Access Token")

_CMD_INTERPRETER = FrameworkRef(Framework.ATTACK, "T1059", "Command and Scripting Interpreter")
_ELEVATION = FrameworkRef(Framework.ATTACK, "T1548", "Abuse Elevation Control Mechanism")
_LLM_AGENCY = FrameworkRef(Framework.OWASP_LLM, "LLM06", "Excessive Agency")

# Static tool-poisoning heuristics (Wave 3 Feature T). Hidden Unicode is
# obfuscation that conceals the payload from a reviewer; an injected instruction
# impersonates a trusted role to hijack the agent. Both are LLM prompt injection
# in the ATLAS/OWASP-LLM sense.
_OBFUSCATION = FrameworkRef(Framework.ATTACK, "T1027", "Obfuscated Files or Information")
_IMPERSONATION = FrameworkRef(Framework.ATTACK, "T1656", "Impersonation")
_ATLAS_PROMPT_INJECTION = FrameworkRef(Framework.ATLAS, "AML.T0051", "LLM Prompt Injection")
_LLM_PROMPT_INJECTION = FrameworkRef(Framework.OWASP_LLM, "LLM01", "Prompt Injection")

# Agent-host logging health (Wave 3 Feature L). Absent/stale logging is the
# silent-log-collection-failure the report ties to Impair Defenses (T1562.003);
# a group/world-readable log both exposes and lets an adversary tamper with the
# audit trail. CIS Control 8 (Audit Log Management) is the direct control match.
_IMPAIR_LOGGING = FrameworkRef(
    Framework.ATTACK, "T1562.003", "Impair Defenses: Impair Command History Logging"
)
_CIS_AUDIT_LOG = FrameworkRef(Framework.CIS, "Control 8", "Audit Log Management")

# Agent Trust Broker posture (governance tier; docs/proposals/ATB_POSTURE_CHECK.md).
# A privileged tool with no broker in front of it is a missing reference monitor
# for a privileged action (T1548, Abuse Elevation Control Mechanism); an
# unverified tool manifest reopens tool-description poisoning — the same LLM
# prompt-injection family the tool-integrity checks map to; a broker whose
# posture cannot be confirmed (audit off, or a manifest that won't parse) is a
# defense left un-operative (T1562, Impair Defenses). Every row also cites NIST
# AI RMF GOVERN — governance is the honest home for the broker family.
_IMPAIR_DEFENSES = FrameworkRef(Framework.ATTACK, "T1562", "Impair Defenses")

# --- the mapping table --------------------------------------------------------
# Key: the finding id a check emits. Value: its citations, strongest-first.
MAPPINGS: dict[str, tuple[FrameworkRef, ...]] = {
    # credential hygiene
    "CRED-PLAINTEXT": (_CREDS_IN_FILES, _ATLAS_CREDS, _LLM_SENSITIVE, _RMF_GOVERN, _CIS_DATA),
    # a plaintext secret in a RUNNING process's environment (Wave 2 Feature G):
    # the same Unsecured-Credentials family as a key in a file, just read live
    # from the process env — so it shares CRED-PLAINTEXT's citation stack
    "CRED-ENV": (_CREDS_IN_FILES, _ATLAS_CREDS, _LLM_SENSITIVE, _RMF_GOVERN, _CIS_DATA),
    "CRED-PERMS": (_CREDS_IN_FILES, _ATLAS_CREDS, _RMF_GOVERN, _CIS_DATA),
    "CRED-GIT": (_CREDS_IN_FILES, _ATLAS_CREDS, _RMF_GOVERN, _CIS_DATA),
    # one credential reused across servers: a compromise pivots via the shared
    # (still valid) credential, so Valid Accounts leads the citation list
    "CRED-REUSE": (_VALID_ACCOUNTS, _CREDS_IN_FILES, _ATLAS_CREDS, _RMF_GOVERN, _CIS_ACCESS),
    # token/credential store at rest: a readable file hands over a live token,
    # so Steal Application Access Token leads; a stale token is the same prize
    # left lying around
    "TOKEN-STORE-PERMS": (
        _STEAL_APP_TOKEN,
        _UNSECURED_CREDS,
        _CREDS_IN_FILES,
        _ATLAS_CREDS,
        _RMF_GOVERN,
        _CIS_DATA,
    ),
    "TOKEN-STORE-EXPIRED": (
        _STEAL_APP_TOKEN,
        _UNSECURED_CREDS,
        _ATLAS_CREDS,
        _RMF_GOVERN,
        _CIS_DATA,
    ),
    # exposure
    "EXPOSE-BIND": (_PUBLIC_FACING, _ATLAS_PUBLIC, _RMF_MANAGE, _CIS_CONFIG),
    "LAN-EXPOSED": (_PUBLIC_FACING, _ATLAS_PUBLIC, _RMF_MANAGE, _CIS_CONFIG),
    # version pinning / supply chain
    "PIN-UNPINNED": (_SUPPLY_CHAIN, _ATLAS_SUPPLY, _LLM_SUPPLY, _RMF_MAP, _CIS_APPSEC),
    "PIN-KNOWN-VULN": (_SUPPLY_CHAIN, _ATLAS_SUPPLY, _LLM_SUPPLY, _RMF_MAP, _CIS_APPSEC),
    # a known-vulnerable dependency (not just the pinned runner) named on a
    # server or process launch command (Wave 3 Feature V)
    "VULN-KNOWN": (_SUPPLY_DEPS, _ATLAS_SUPPLY, _LLM_SUPPLY, _RMF_MAP, _CIS_APPSEC),
    # tool scope / agency
    "SCOPE-DANGEROUS-ALLOW": (_CMD_INTERPRETER, _LLM_AGENCY, _RMF_MANAGE, _CIS_ACCESS),
    "SCOPE-DANGEROUS-AUTOAPPROVE": (_CMD_INTERPRETER, _LLM_AGENCY, _RMF_MANAGE, _CIS_ACCESS),
    "SCOPE-WILDCARD": (_ELEVATION, _LLM_AGENCY, _RMF_MANAGE, _CIS_ACCESS),
    "SCOPE-AUTOAPPROVE-WILDCARD": (_ELEVATION, _LLM_AGENCY, _RMF_MANAGE, _CIS_ACCESS),
    # tool integrity / poisoning (Wave 3 Feature T)
    "TOOL-HIDDEN-UNICODE": (
        _OBFUSCATION,
        _ATLAS_PROMPT_INJECTION,
        _LLM_PROMPT_INJECTION,
        _RMF_MANAGE,
        _CIS_APPSEC,
    ),
    "TOOL-INJECTION-TEXT": (
        _IMPERSONATION,
        _ATLAS_PROMPT_INJECTION,
        _LLM_PROMPT_INJECTION,
        _RMF_MANAGE,
        _CIS_APPSEC,
    ),
    # agent-host logging health / telemetry (Wave 3 Feature L)
    "TELEMETRY-ABSENT": (_IMPAIR_LOGGING, _RMF_MANAGE, _CIS_AUDIT_LOG),
    "TELEMETRY-STALE": (_IMPAIR_LOGGING, _RMF_MANAGE, _CIS_AUDIT_LOG),
    "TELEMETRY-PERMS": (_IMPAIR_LOGGING, _RMF_GOVERN, _CIS_AUDIT_LOG, _CIS_DATA),
    # Agent Trust Broker posture / governance (ATB_POSTURE_CHECK.md)
    "BROKER-ABSENT": (_ELEVATION, _LLM_AGENCY, _RMF_GOVERN, _CIS_ACCESS),
    "BROKER-MANIFEST-UNVERIFIED": (
        _IMPERSONATION,
        _ATLAS_PROMPT_INJECTION,
        _LLM_PROMPT_INJECTION,
        _RMF_GOVERN,
        _CIS_APPSEC,
    ),
    "BROKER-NO-AUDIT": (_IMPAIR_LOGGING, _RMF_GOVERN, _CIS_AUDIT_LOG),
    "BROKER-ALLOWLIST-PERMISSIVE": (_ELEVATION, _LLM_AGENCY, _RMF_GOVERN, _CIS_ACCESS),
    "BROKER-PARSE-ERROR": (_IMPAIR_DEFENSES, _RMF_GOVERN, _CIS_CONFIG),
    # Inspection health: a host config the scanner could not read or parse. Maps
    # to Impair Defenses because an unparseable config is a defence-evasion
    # primitive — the surface goes un-inspected while the host may still load it.
    "CONFIG-UNREADABLE": (_IMPAIR_DEFENSES, _RMF_MANAGE, _CIS_CONFIG),
    # The detection catalog itself is a tampering target: whoever can write
    # the store decides what counts as a secret, so this is defence evasion
    # via the tool's own supply of detection content.
    "DATAPACK-STORE-PERMS": (_IMPAIR_DEFENSES, _SUPPLY_CHAIN, _RMF_GOVERN, _CIS_CONFIG),
}


def refs_for(check_id: str) -> tuple[FrameworkRef, ...]:
    """The citations for one check id (empty for an unknown id — fail soft)."""
    return MAPPINGS.get(check_id, ())
