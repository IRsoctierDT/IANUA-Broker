# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 renderer (GitHub code-scanning integration).

Emits a deterministic, byte-stable SARIF log (sorted keys, no timestamps) that
``github/codeql-action/upload-sarif`` can ingest to raise code-scanning alerts.
Secrets are never present — findings carry only the redacted fingerprint,
exactly like every other renderer (architecture refinement R1).

GitHub maps a result to a file in the checkout when its ``artifactLocation.uri``
is repo-relative, so paths under ``base`` (the scanned root) are emitted
relative to it. Paths outside the repo (e.g. user-home host configs) keep the
``~`` privacy relativization and simply don't annotate — they still appear in
the log.

Scope: SARIF is a *source-file* format and GitHub requires every result URI to
share the checkout's ``file`` scheme, so findings without a filesystem location
— running-socket exposure, whose location is a ``host:port`` endpoint — are
**omitted** from the file-scoped (default) view. They remain in the terminal,
JSON, and HTML renderers.

Logical locations (ADR-16): with ``logical_locations=True``, a non-file finding
is instead emitted as a SARIF ``logicalLocation`` (a network endpoint, not a
synthetic file). This is how ``lan --sarif`` produces standards-valid SARIF for
generic consumers (SIEM/audit pipelines, SARIF tooling) — **not** GitHub code
scanning, which needs a physical file to raise an alert. The default ``scan``
view keeps ``logical_locations=False`` so its GitHub integration is unchanged.
"""

from __future__ import annotations

import hashlib
import json

from .. import __version__
from ..domain import Finding, Report, Severity
from . import RenderOptions, display_path
from .common import ordered_findings, secret_str

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "ai-agentic-mcpscan"
INFORMATION_URI = "https://github.com/IRsoctierDT/IANUA-Broker"

# Severity -> SARIF result level (error | warning | note).
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Severity -> GitHub ``security-severity`` score (drives the alert's severity band).
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}


def _source_uri(path: str, base: str | None, opts: RenderOptions) -> str | None:
    """Map a finding location to a SARIF ``artifactLocation.uri``, or ``None``.

    Returns ``None`` for non-filesystem locations (a ``scheme://`` URI, or a
    ``host:port`` network endpoint) — GitHub code scanning requires every result
    URI to share the checkout's ``file`` scheme, so such findings are dropped
    from the SARIF (they remain in the other renderers).

    For filesystem paths: repo-relative when under ``base`` (so GitHub can
    annotate the file); otherwise ``~``-privatized and, if still absolute,
    expressed as a ``file://`` URI.
    """
    if "://" in path:
        return None  # scheme-based non-file location, e.g. socket://host:port
    norm = path.replace("\\", "/")
    first = norm.split("/", 1)[0]
    # A colon in the first segment that is not a Windows drive letter marks a
    # network endpoint (host:port), not a file — out of scope for code scanning.
    if ":" in first and not (len(first) == 2 and first[1] == ":"):
        return None
    if base:
        b = base.replace("\\", "/").rstrip("/")
        if norm == b:
            return "."
        if norm.startswith(b + "/"):
            return norm[len(b) + 1 :]
    disp = display_path(path, opts).replace("\\", "/")
    if disp.startswith("/"):
        return "file://" + disp
    if len(disp) > 2 and disp[1] == ":":  # Windows drive, e.g. C:/Users/...
        return "file:///" + disp
    return disp  # already relative, or ~/… privacy form


def _network_endpoint(path: str) -> str | None:
    """Return the ``host:port`` endpoint a non-file location names, or ``None``.

    Recognizes a scheme-prefixed endpoint (``lan://h:p``, ``socket://h:p``) and a
    bare ``host:port`` — but not a filesystem path or a Windows drive.
    """
    endpoint = path.split("://", 1)[1] if "://" in path else path
    norm = endpoint.replace("\\", "/")
    # A filesystem path (incl. any Windows drive like ``C:\…``) has a separator;
    # a bare ``host:port`` — IPv4 or bracketed IPv6 — does not.
    if "/" in norm:
        return None
    if ":" not in norm:
        return None
    return endpoint


def _logical_location(endpoint: str) -> dict[str, object]:
    """A SARIF ``logicalLocation`` for a network endpoint (ADR-16)."""
    return {
        "name": endpoint,
        "fullyQualifiedName": f"lan://{endpoint}",
        "kind": "resource",
    }


def _message(finding: Finding, opts: RenderOptions) -> str:
    """Human-readable result message (redaction-safe — never a raw secret)."""
    parts = [f"{finding.title}.", finding.rationale, f"Remediation: {finding.remediation}"]
    sstr = secret_str(finding.secret, opts)
    if sstr is not None:
        parts.append(f"Secret: {sstr}")
    return " ".join(p for p in parts if p)


def _partial_fingerprint(finding: Finding, uri: str) -> str:
    """Stable per-result fingerprint so GitHub tracks alerts across commits."""
    line = "" if finding.location.line is None else str(finding.location.line)
    secret = "" if finding.secret is None else finding.secret.sha256_8
    material = f"{finding.id}\x1f{uri}\x1f{line}\x1f{secret}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "name": finding.id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.rationale},
        "help": {"text": finding.remediation},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": ["security", finding.dimension.value],
        },
    }


def report_to_sarif(
    report: Report,
    opts: RenderOptions | None = None,
    *,
    base: str | None = None,
    logical_locations: bool = False,
) -> dict[str, object]:
    """Convert a Report to a SARIF 2.1.0 log dict (stable shape).

    Args:
        report: The scan result.
        opts: Cross-renderer display options (path privacy, secret reveal).
        base: Absolute path of the scanned root; locations under it become
            repo-relative URIs so GitHub code scanning can annotate them.
        logical_locations: When True, a non-file finding (a ``host:port``
            network endpoint) is emitted as a SARIF ``logicalLocation`` instead
            of being dropped (ADR-16). Used by ``lan --sarif``; the default
            file-scoped ``scan`` view keeps this False.
    """
    opts = opts or RenderOptions()
    rules: list[dict[str, object]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, object]] = []

    def _register(finding: Finding) -> int:
        if finding.id not in rule_index:
            rule_index[finding.id] = len(rules)
            rules.append(_rule(finding))
        return rule_index[finding.id]

    def _result(finding: Finding, location: dict[str, object], fp_key: str) -> dict[str, object]:
        return {
            "ruleId": finding.id,
            "ruleIndex": _register(finding),
            "level": _LEVEL[finding.severity],
            "message": {"text": _message(finding, opts)},
            "locations": [location],
            "partialFingerprints": {"mcpscanFindingHash/v1": _partial_fingerprint(finding, fp_key)},
        }

    for server in report.servers:
        for finding in ordered_findings(server):
            uri = _source_uri(finding.location.path, base, opts)
            if uri is not None:
                physical: dict[str, object] = {"artifactLocation": {"uri": uri}}
                if finding.location.line is not None and finding.location.line >= 1:
                    physical["region"] = {"startLine": finding.location.line}
                results.append(_result(finding, {"physicalLocation": physical}, uri))
                continue
            # Non-file location. Emit a logical location when asked; otherwise
            # drop it (the file-scoped GitHub view can't represent it).
            endpoint = _network_endpoint(finding.location.path) if logical_locations else None
            if endpoint is None:
                continue
            logical = _logical_location(endpoint)
            results.append(
                _result(
                    finding, {"logicalLocations": [logical]}, str(logical["fullyQualifiedName"])
                )
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": INFORMATION_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(
    report: Report,
    opts: RenderOptions | None = None,
    *,
    base: str | None = None,
    logical_locations: bool = False,
) -> str:
    """Render a Report as deterministic, byte-stable SARIF 2.1.0 JSON text.

    ``logical_locations=True`` represents non-file (network-endpoint) findings as
    SARIF logical locations (ADR-16) — used by ``lan --sarif``.
    """
    payload = report_to_sarif(report, opts, base=base, logical_locations=logical_locations)
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
