"""SARIF 2.1.0 renderer tests: shape, level/severity mapping, redaction, URIs."""

from __future__ import annotations

import json

from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    Server,
    ServerState,
    Severity,
)
from mcpscan.redaction import fingerprint_secret
from mcpscan.report import RenderOptions
from mcpscan.report.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    render_sarif,
    report_to_sarif,
)

RAW_SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123456789"


def _finding(**kw: object) -> Finding:
    base: dict[str, object] = {
        "id": "CRED-PLAINTEXT",
        "dimension": Dimension.CREDENTIAL,
        "severity": Severity.CRITICAL,
        "title": "Plaintext OpenAI API key in config",
        "location": Location(path="/repo/.mcp.json", line=4),
        "remediation": "Move it to a secret manager and rotate the key.",
        "rationale": "Plaintext credentials are trivially exfiltrated.",
        "secret": fingerprint_secret(RAW_SECRET),
    }
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def _report(*findings: Finding) -> Report:
    server = Server(
        id="/repo/.mcp.json#leaky",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=findings or (_finding(),),
    )
    return Report(
        schema_version="1.0",
        servers=(server,),
        overall_grade="F",
        dimension_grades={Dimension.CREDENTIAL: "F"},
    )


def test_top_level_sarif_shape() -> None:
    doc = json.loads(render_sarif(_report()))
    assert doc["$schema"] == SARIF_SCHEMA
    assert doc["version"] == SARIF_VERSION
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == TOOL_NAME
    assert driver["informationUri"].startswith("https://")
    assert isinstance(driver["version"], str) and driver["version"]


def test_result_and_rule_are_linked() -> None:
    doc = json.loads(render_sarif(_report()))
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert len(rules) == 1
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "CRED-PLAINTEXT"
    assert rules[r["ruleIndex"]]["id"] == "CRED-PLAINTEXT"


def test_critical_maps_to_error_and_security_severity() -> None:
    doc = json.loads(render_sarif(_report()))
    run = doc["runs"][0]
    assert run["results"][0]["level"] == "error"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "9.5"
    assert "security" in rule["properties"]["tags"]
    assert "credential" in rule["properties"]["tags"]


def test_medium_maps_to_warning() -> None:
    f = _finding(
        id="PIN-UNPINNED",
        dimension=Dimension.PINNING,
        severity=Severity.MEDIUM,
        secret=None,
    )
    doc = json.loads(render_sarif(_report(f)))
    assert doc["runs"][0]["results"][0]["level"] == "warning"
    assert doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "5.0"


def test_duplicate_finding_ids_share_one_rule() -> None:
    doc = json.loads(
        render_sarif(
            _report(_finding(), _finding(location=Location(path="/repo/.mcp.json", line=9)))
        )
    )
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1  # deduped
    assert len(run["results"]) == 2
    assert {res["ruleIndex"] for res in run["results"]} == {0}


def test_region_only_present_when_line_known() -> None:
    with_line = json.loads(render_sarif(_report(_finding())))  # default location has line=4
    loc = with_line["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] == 4

    no_line = json.loads(render_sarif(_report(_finding(location=Location(path="/repo/.mcp.json")))))
    loc2 = no_line["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in loc2


def test_uri_is_repo_relative_under_base() -> None:
    doc = json.loads(render_sarif(_report(), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == ".mcp.json"  # repo-relative -> GitHub can annotate it


def test_uri_outside_base_is_privatized_file_url() -> None:
    f = _finding(location=Location(path="/home/jane/.cursor/mcp.json"))
    doc = json.loads(render_sarif(_report(f), RenderOptions(home="/home/jane"), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "~/.cursor/mcp.json"  # ~ privacy, no username leak
    assert "jane" not in uri


def test_scheme_location_is_excluded() -> None:
    # A scheme-based non-file location (socket://…) is out of scope for code
    # scanning — GitHub requires every result URI to share the file scheme.
    f = _finding(
        id="EXPOSURE-WILDCARD",
        dimension=Dimension.EXPOSURE,
        severity=Severity.HIGH,
        location=Location(path="socket://0.0.0.0:8000"),
        secret=None,
    )
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_bare_host_port_finding_is_excluded() -> None:
    # A running-socket finding (EXPOSE-BIND) uses a scheme-less "host:port"
    # location with no source file. GitHub rejects a non-file URI, so it is
    # dropped from the SARIF (it still appears in the other renderers).
    f = _finding(
        id="EXPOSE-BIND",
        dimension=Dimension.EXPOSURE,
        severity=Severity.HIGH,
        location=Location(path="0.0.0.0:22"),
        secret=None,
    )
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    assert doc["runs"][0]["results"] == []


def test_file_findings_kept_when_mixed_with_network_findings() -> None:
    # A file finding survives; a co-occurring host:port finding is dropped.
    file_f = _finding(location=Location(path="/repo/.mcp.json", line=4))
    net_f = _finding(
        id="EXPOSE-BIND",
        severity=Severity.HIGH,
        location=Location(path="0.0.0.0:22"),
        secret=None,
    )
    doc = json.loads(render_sarif(_report(file_f, net_f), base="/repo"))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == ".mcp.json"
    # Every emitted URI is file-scoped: relative, or file://…, never a bare host:port.
    for res in results:
        u = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert u.startswith("file://") or ":" not in u.split("/", 1)[0]


def test_path_equal_to_base_becomes_dot() -> None:
    f = _finding(location=Location(path="/repo"))
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "."


def test_windows_absolute_path_becomes_file_uri() -> None:
    # Outside base, an absolute Windows path (no ~ relativization) -> file:/// URI.
    f = _finding(location=Location(path=r"C:\Users\jane\.mcp.json"))
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "file:///C:/Users/jane/.mcp.json"


def test_message_and_log_never_contain_raw_secret() -> None:
    out = render_sarif(_report(), RenderOptions(home="/home/jane"), base="/repo")
    assert RAW_SECRET not in out
    msg = json.loads(out)["runs"][0]["results"][0]["message"]["text"]
    assert "[redacted" in msg  # fingerprint form, never the raw value


def test_show_secrets_reveals_masked_only() -> None:
    out = render_sarif(_report(), RenderOptions(show_secrets=True), base="/repo")
    assert RAW_SECRET not in out  # masked (first-2/last-2), never raw


def test_partial_fingerprint_is_stable_and_present() -> None:
    a = json.loads(render_sarif(_report(), base="/repo"))
    b = json.loads(render_sarif(_report(), base="/repo"))
    fp = a["runs"][0]["results"][0]["partialFingerprints"]["mcpscanFindingHash/v1"]
    assert fp == b["runs"][0]["results"][0]["partialFingerprints"]["mcpscanFindingHash/v1"]
    assert len(fp) == 16


def test_render_is_byte_stable() -> None:
    assert render_sarif(_report(), base="/repo") == render_sarif(_report(), base="/repo")


def test_clean_report_is_valid_empty_run() -> None:
    clean = Report(schema_version="1.0", servers=(), overall_grade="A", dimension_grades={})
    doc = report_to_sarif(clean)
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


# --- acceptance suppressions (Wave 1 Feature D) ---
def _acceptance(*, expired: bool = False) -> object:
    from mcpscan.domain import Acceptance

    return Acceptance(
        owner="Jane Doe",
        accepted="2026-08-11",
        expires="2026-11-11",
        reason="CI runner is ephemeral",
        expired=expired,
    )


def test_unexpired_acceptance_emits_suppression() -> None:
    f = _finding(
        id="SCOPE-DANGEROUS-ALLOW",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        secret=None,
        acceptance=_acceptance(),
    )
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    suppression = doc["runs"][0]["results"][0]["suppressions"][0]
    assert suppression == {
        "kind": "external",
        "status": "accepted",
        "justification": "Accepted by Jane Doe until 2026-11-11: CI runner is ephemeral",
    }


def test_expired_acceptance_emits_no_suppression() -> None:
    f = _finding(
        id="SCOPE-DANGEROUS-ALLOW",
        dimension=Dimension.TOOL_SCOPE,
        severity=Severity.HIGH,
        secret=None,
        acceptance=_acceptance(expired=True),
    )
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    assert "suppressions" not in doc["runs"][0]["results"][0]


def test_unaccepted_finding_has_no_suppressions_key() -> None:
    doc = json.loads(render_sarif(_report(), base="/repo"))
    assert "suppressions" not in doc["runs"][0]["results"][0]


# --- logical locations for network endpoints (ADR-16, lan --sarif) ---
def test_logical_locations_emit_network_endpoint() -> None:
    f = _finding(
        id="LAN-EXPOSED",
        dimension=Dimension.EXPOSURE,
        severity=Severity.HIGH,
        location=Location(path="192.168.10.20:3000"),
        secret=None,
    )
    doc = json.loads(render_sarif(_report(f), logical_locations=True))
    result = doc["runs"][0]["results"][0]
    loc = result["locations"][0]
    assert "physicalLocation" not in loc  # never a synthetic file
    logical = loc["logicalLocations"][0]
    assert logical == {
        "name": "192.168.10.20:3000",
        "fullyQualifiedName": "lan://192.168.10.20:3000",
        "kind": "resource",
    }
    assert doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "LAN-EXPOSED"


def test_logical_locations_strip_scheme_prefix() -> None:
    # A scheme-prefixed endpoint (lan://, socket://) yields the bare host:port.
    f = _finding(
        id="LAN-EXPOSED",
        severity=Severity.HIGH,
        location=Location(path="socket://10.0.0.5:8000"),
        secret=None,
    )
    doc = json.loads(render_sarif(_report(f), logical_locations=True))
    logical = doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
    assert logical["name"] == "10.0.0.5:8000"


def test_logical_locations_off_by_default_still_drops_endpoints() -> None:
    # The file-scoped scan view is unchanged: no logical_locations flag => dropped.
    f = _finding(
        id="LAN-EXPOSED",
        severity=Severity.HIGH,
        location=Location(path="192.168.10.20:3000"),
        secret=None,
    )
    doc = json.loads(render_sarif(_report(f)))
    assert doc["runs"][0]["results"] == []


def test_logical_locations_keep_file_findings_physical() -> None:
    # With the flag on, a file finding still gets a physicalLocation (mixed run).
    file_f = _finding(location=Location(path="/repo/.mcp.json", line=4))
    net_f = _finding(
        id="LAN-EXPOSED",
        severity=Severity.HIGH,
        location=Location(path="192.168.10.20:3000"),
        secret=None,
    )
    doc = json.loads(render_sarif(_report(file_f, net_f), base="/repo", logical_locations=True))
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    kinds = {("physicalLocation" in r["locations"][0]) for r in results}
    assert kinds == {True, False}  # one physical, one logical


def test_logical_location_fingerprints_are_distinct_per_endpoint() -> None:
    a = _finding(id="LAN-EXPOSED", severity=Severity.HIGH, location=Location(path="10.0.0.1:3000"))
    b = _finding(id="LAN-EXPOSED", severity=Severity.HIGH, location=Location(path="10.0.0.2:3000"))
    doc = json.loads(render_sarif(_report(a, b), logical_locations=True))
    fps = {r["partialFingerprints"]["mcpscanFindingHash/v1"] for r in doc["runs"][0]["results"]}
    assert len(fps) == 2  # different endpoints -> different fingerprints


def test_network_endpoint_helper_recognizes_and_rejects() -> None:
    from mcpscan.report.sarif import _network_endpoint

    assert _network_endpoint("192.168.1.5:3000") == "192.168.1.5:3000"
    assert _network_endpoint("lan://10.0.0.1:8000") == "10.0.0.1:8000"
    assert _network_endpoint("socket://[::1]:9000") == "[::1]:9000"
    # A path component means it's a file-ish location, not a bare endpoint.
    assert _network_endpoint("0.0.0.0:8000/mcp") is None
    # A scheme URL with no port has no colon in the endpoint.
    assert _network_endpoint("lan://justahostname") is None
    # A Windows drive is a file, never an endpoint.
    assert _network_endpoint("C:/Users/jane/.mcp.json") is None
