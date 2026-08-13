# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Signed data-pack refresh channel (Wave 3 Feature D).

Covers the pure catalog model (parse/serialize round-trip, fail-closed
validation), the compiled catalogs that drive detection, the verify-or-refuse
signed load (injected stub verifier + a real ed25519 end-to-end), the local
store, the engine active-pack wiring (byte-identical default, a custom pack
changing which secrets match, a corrupt store falling back to the built-in), the
OS-appropriate store path, and the ``update-datapack`` CLI (verify-fail writes
nothing; success installs). No network is ever touched.
"""

from __future__ import annotations

import base64
import json
import os
import platform
from dataclasses import replace
from pathlib import Path, PureWindowsPath

import pytest

from mcpscan.adapters.base import ServerDecl
from mcpscan.adapters.paths import datapack_store_path
from mcpscan.checks.secrets import check_server_env
from mcpscan.cli import main
from mcpscan.datapack import (
    DATAPACK_ED25519_CONTEXT,
    DataPack,
    DataPackError,
    builtin_datapack,
    compile_agent_catalog,
    compile_secret_catalog,
    datapack_to_json,
    first_allowed_signer,
    load_local_datapack,
    load_verified_datapack,
    parse_datapack,
)
from mcpscan.discovery.process_env import looks_like_agent
from mcpscan.engine import scan
from mcpscan.lan.verify import VerifyResult

# A synthetic secret shape that NO built-in pattern (and no entropy rule on a
# non-secret-named key) matches, so it is flagged only when a custom pack adds a
# pattern for it — the load-bearing "the pack changes detection" fixture.
_CUSTOM_LABEL = "Acme deploy token"
_CUSTOM_PATTERN = r"acme-[0-9]{10}"
_CUSTOM_VALUE = "acme-1234567890"


def _custom_pack() -> DataPack:
    """The built-in pack plus one extra provider pattern and one extra marker."""
    base = builtin_datapack()
    return replace(
        base,
        provider_patterns=base.provider_patterns + ((_CUSTOM_LABEL, _CUSTOM_PATTERN),),
        agent_markers=base.agent_markers + ("acmeagent",),
    )


def _ok_verifier(*_a: object) -> VerifyResult:
    return VerifyResult(True, "ok")


def _bad_verifier(*_a: object) -> VerifyResult:
    return VerifyResult(False, "signature rejected: tampered")


# --- pure model: parse / serialize round-trip -------------------------------
def test_builtin_datapack_round_trips_through_parse() -> None:
    pack = builtin_datapack()
    parsed = parse_datapack(datapack_to_json(pack))
    assert parsed == pack


def test_custom_pack_round_trips_through_parse() -> None:
    pack = _custom_pack()
    parsed = parse_datapack(datapack_to_json(pack))
    assert parsed == pack


# --- pure model: fail-closed validation -------------------------------------
def test_parse_rejects_non_json() -> None:
    assert isinstance(parse_datapack("{not json"), DataPackError)


def test_parse_rejects_non_object() -> None:
    err = parse_datapack("[]")
    assert isinstance(err, DataPackError)
    assert "JSON object" in err.message


def test_parse_rejects_missing_schema_version() -> None:
    raw = datapack_to_json(builtin_datapack()).replace('"schema_version": "1.0",', "")
    err = parse_datapack(raw)
    assert isinstance(err, DataPackError)
    assert "schema_version" in err.message


def test_parse_rejects_invalid_provider_regex() -> None:
    pack = replace(builtin_datapack(), provider_patterns=(("bad", "("),))
    err = parse_datapack(datapack_to_json(pack))
    assert isinstance(err, DataPackError)
    assert "invalid regex" in err.message


def test_parse_rejects_invalid_secret_name_regex() -> None:
    pack = replace(builtin_datapack(), secret_name_pattern="(unbalanced")
    err = parse_datapack(datapack_to_json(pack))
    assert isinstance(err, DataPackError)
    assert "secret_name_pattern" in err.message


def test_parse_rejects_boolean_entropy_threshold() -> None:
    # A JSON ``true`` must not be silently read as the number 1.
    raw = datapack_to_json(builtin_datapack()).replace(
        '"entropy_threshold": 3.5', '"entropy_threshold": true'
    )
    err = parse_datapack(raw)
    assert isinstance(err, DataPackError)
    assert "entropy_threshold" in err.message


def test_parse_rejects_negative_min_len() -> None:
    raw = datapack_to_json(builtin_datapack()).replace(
        '"min_entropy_len": 20', '"min_entropy_len": 0'
    )
    err = parse_datapack(raw)
    assert isinstance(err, DataPackError)
    assert "min_entropy_len" in err.message


def test_parse_rejects_empty_agent_markers() -> None:
    pack = replace(builtin_datapack(), agent_markers=())
    err = parse_datapack(datapack_to_json(pack))
    assert isinstance(err, DataPackError)
    assert "agent_markers" in err.message


def test_parse_allows_empty_token_store_templates() -> None:
    pack = replace(builtin_datapack(), token_store_templates=())
    parsed = parse_datapack(datapack_to_json(pack))
    assert isinstance(parsed, DataPack)
    assert parsed.token_store_templates == ()


# --- compiled catalogs drive detection --------------------------------------
def test_builtin_catalog_flags_anthropic_key() -> None:
    catalog = compile_secret_catalog(builtin_datapack())
    server = ServerDecl(
        name="x", command="node", env=(("ANTHROPIC_API_KEY", "sk-ant-" + "A" * 30),)
    )
    findings = check_server_env(server, "/cfg.json", catalog=catalog)
    assert [f.id for f in findings] == ["CRED-PLAINTEXT"]


def test_builtin_catalog_does_not_flag_custom_shaped_value() -> None:
    # Regression guard: the default pack must not flag the custom-shaped value.
    server = ServerDecl(name="x", command="node", env=(("DEPLOY", _CUSTOM_VALUE),))
    assert check_server_env(server, "/cfg.json") == []


def test_custom_provider_pattern_flags_new_secret() -> None:
    catalog = compile_secret_catalog(_custom_pack())
    server = ServerDecl(name="x", command="node", env=(("DEPLOY", _CUSTOM_VALUE),))
    findings = check_server_env(server, "/cfg.json", catalog=catalog)
    assert [f.id for f in findings] == ["CRED-PLAINTEXT"]
    assert _CUSTOM_LABEL in findings[0].title


def test_compile_agent_catalog_builtin_matches_today() -> None:
    catalog = compile_agent_catalog(builtin_datapack())
    assert looks_like_agent("npx -y @modelcontextprotocol/server-fs", catalog=catalog)
    assert not looks_like_agent("python /home/u/train.py", catalog=catalog)
    # Word-boundary discipline preserved: 'zed' must not match 'authorized'.
    assert not looks_like_agent("/usr/lib/systemd/systemd-authorized", catalog=catalog)


def test_custom_agent_marker_only_matches_with_pack() -> None:
    text = "/opt/acmeagent/bin/acmeagent --stdio"
    assert not looks_like_agent(text)  # built-in has no 'acmeagent' marker
    assert looks_like_agent(text, catalog=compile_agent_catalog(_custom_pack()))


def test_compile_agent_catalog_empty_markers_never_matches() -> None:
    empty = compile_agent_catalog(replace(builtin_datapack(), agent_markers=()))
    assert not looks_like_agent("claude mcp cursor", catalog=empty)


# --- verify-or-refuse signed load (injected verifier) -----------------------
def _write_pack(tmp_path: Path, pack: DataPack) -> Path:
    path = tmp_path / "pack.json"
    path.write_text(datapack_to_json(pack), encoding="utf-8")
    return path


def test_load_verified_ok_with_stub_verifier(tmp_path: Path) -> None:
    pack_path = _write_pack(tmp_path, _custom_pack())
    loaded = load_verified_datapack(
        pack_path,
        tmp_path / "sig",
        tmp_path / "signers",
        operator="op",
        verifier=_ok_verifier,
    )
    assert isinstance(loaded, DataPack)
    # The verified pack really does change which secrets match.
    catalog = compile_secret_catalog(loaded)
    server = ServerDecl(name="x", command="node", env=(("DEPLOY", _CUSTOM_VALUE),))
    assert check_server_env(server, "/cfg.json", catalog=catalog)


def test_load_verified_refused_on_bad_signature(tmp_path: Path) -> None:
    pack_path = _write_pack(tmp_path, _custom_pack())
    err = load_verified_datapack(
        pack_path,
        tmp_path / "sig",
        tmp_path / "signers",
        operator="op",
        verifier=_bad_verifier,
    )
    assert isinstance(err, DataPackError)
    assert "refused" in err.message and "tampered" in err.message


def test_load_verified_refuses_malformed_pack_even_when_signed(tmp_path: Path) -> None:
    # A signature can vouch for bytes that are still not a valid pack.
    pack_path = tmp_path / "pack.json"
    pack_path.write_text("{not a pack", encoding="utf-8")
    err = load_verified_datapack(
        pack_path, tmp_path / "sig", tmp_path / "signers", operator="op", verifier=_ok_verifier
    )
    assert isinstance(err, DataPackError)


def test_load_verified_unsupported_scheme(tmp_path: Path) -> None:
    err = load_verified_datapack(
        tmp_path / "pack.json",
        tmp_path / "sig",
        tmp_path / "signers",
        operator="op",
        scheme="pgp",
    )
    assert isinstance(err, DataPackError)
    assert "unsupported" in err.message


def test_load_verified_missing_pack_file(tmp_path: Path) -> None:
    err = load_verified_datapack(
        tmp_path / "absent.json",
        tmp_path / "sig",
        tmp_path / "signers",
        operator="op",
        verifier=_ok_verifier,
    )
    assert isinstance(err, DataPackError)
    assert "cannot read" in err.message


def test_load_verified_default_ssh_verifier_refuses_bogus_signature(tmp_path: Path) -> None:
    # Exercises the real ssh verifier path (no injected verifier). Whether
    # ssh-keygen is present or not, a bogus signature yields ok=False -> refused.
    pack_path = _write_pack(tmp_path, builtin_datapack())
    sig = tmp_path / "pack.sig"
    sig.write_text("not a real signature\n", encoding="utf-8")
    signers = tmp_path / "signers"
    signers.write_text("packpub@example.com ssh-ed25519 AAAAbogus\n", encoding="utf-8")
    err = load_verified_datapack(pack_path, sig, signers, operator="packpub@example.com")
    assert isinstance(err, DataPackError)
    assert "refused" in err.message


# --- verify-or-refuse: real ed25519 end-to-end ------------------------------
def _crypto_backend_works() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        Ed25519PrivateKey.generate().sign(b"x")
    except BaseException:  # noqa: BLE001 - broken native backends raise non-ImportError
        return False
    return True


_needs_crypto = pytest.mark.skipif(not _crypto_backend_works(), reason="cryptography unavailable")


def _sign_ed25519(tmp_path: Path, pack: DataPack, operator: str = "packpub@example.com"):  # type: ignore[no-untyped-def]
    """Write a pack, an ed25519 detached signature over its bytes, and signers."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pack_path = _write_pack(tmp_path, pack)
    key = Ed25519PrivateKey.generate()
    # The datapack ed25519 channel is domain-separated: the signer signs the
    # context prefix + the pack bytes (raw signatures carry no namespace field).
    sig = key.sign(DATAPACK_ED25519_CONTEXT + pack_path.read_bytes())
    sig_path = tmp_path / "pack.sig"
    sig_path.write_bytes(base64.b64encode(sig))
    signers = tmp_path / "signers"
    signers.write_text(
        f"{operator} {base64.b64encode(key.public_key().public_bytes_raw()).decode()}\n",
        encoding="utf-8",
    )
    return pack_path, sig_path, signers, operator


@_needs_crypto
def test_load_verified_ed25519_end_to_end(tmp_path: Path) -> None:
    pack_path, sig, signers, op = _sign_ed25519(tmp_path, _custom_pack())
    loaded = load_verified_datapack(pack_path, sig, signers, operator=op, scheme="ed25519")
    assert isinstance(loaded, DataPack)
    assert (_CUSTOM_LABEL, _CUSTOM_PATTERN) in loaded.provider_patterns


@_needs_crypto
def test_load_verified_ed25519_tampered_is_refused(tmp_path: Path) -> None:
    pack_path, sig, signers, op = _sign_ed25519(tmp_path, _custom_pack())
    pack_path.write_text(datapack_to_json(builtin_datapack()), encoding="utf-8")  # tamper
    err = load_verified_datapack(pack_path, sig, signers, operator=op, scheme="ed25519")
    assert isinstance(err, DataPackError)


@_needs_crypto
def test_ed25519_signature_without_datapack_context_is_refused(tmp_path: Path) -> None:
    # Domain separation: a signature over the RAW pack bytes (the un-prefixed form
    # the LAN channel uses) must NOT verify for the datapack channel.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pack = _custom_pack()
    pack_path = _write_pack(tmp_path, pack)
    key = Ed25519PrivateKey.generate()
    sig = key.sign(pack_path.read_bytes())  # NO context prefix — wrong domain
    (tmp_path / "pack.sig").write_bytes(base64.b64encode(sig))
    (tmp_path / "signers").write_text(
        f"op@example.com {base64.b64encode(key.public_key().public_bytes_raw()).decode()}\n",
        encoding="utf-8",
    )
    err = load_verified_datapack(
        pack_path,
        tmp_path / "pack.sig",
        tmp_path / "signers",
        operator="op@example.com",
        scheme="ed25519",
    )
    assert isinstance(err, DataPackError)
    assert "refused" in err.message


# --- local store load -------------------------------------------------------
def test_load_local_datapack_missing_returns_none(tmp_path: Path) -> None:
    assert load_local_datapack(tmp_path / "absent.json") is None


def test_load_local_datapack_garbage_returns_none(tmp_path: Path) -> None:
    store = tmp_path / "datapack.json"
    store.write_text("{corrupt", encoding="utf-8")
    assert load_local_datapack(store) is None


def test_load_local_datapack_valid_returns_pack(tmp_path: Path) -> None:
    store = tmp_path / "datapack.json"
    store.write_text(datapack_to_json(_custom_pack()), encoding="utf-8")
    loaded = load_local_datapack(store)
    assert loaded == _custom_pack()


# --- OS-appropriate store path ----------------------------------------------
def test_store_path_posix_default() -> None:
    p = datapack_store_path("Linux", {"HOME": "/home/jane"})
    assert str(p) == "/home/jane/.config/mcpscan/datapack.json"


def test_store_path_honours_xdg() -> None:
    p = datapack_store_path("Linux", {"HOME": "/home/jane", "XDG_CONFIG_HOME": "/cfg"})
    assert str(p) == "/cfg/mcpscan/datapack.json"


def test_store_path_windows() -> None:
    p = datapack_store_path("Windows", {"APPDATA": r"C:\Users\jane\AppData\Roaming"})
    assert isinstance(p, PureWindowsPath)
    assert p.name == "datapack.json"
    assert "mcpscan" in str(p)


def test_store_path_none_without_home() -> None:
    assert datapack_store_path("Linux", {}) is None
    assert datapack_store_path("Windows", {}) is None


# --- engine active-pack wiring ----------------------------------------------
_FIXTURE = json.dumps(
    {"mcpServers": {"svc": {"command": "node", "env": {"DEPLOY": _CUSTOM_VALUE}}}}
)


def _scan_ids(
    tmp_path: Path,
    *,
    home: Path | None = None,
    system: str = "Linux",
    env: dict[str, str] | None = None,
) -> set[str]:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / ".mcp.json").write_text(_FIXTURE, encoding="utf-8")
    if env is None:
        env = {"HOME": str(home)} if home is not None else {}
    report = scan(roots=[project], system=system, env=env, enumerate_sockets=False)
    return {f.id for s in report.servers for f in s.findings}


def test_default_scan_is_builtin_and_byte_identical(tmp_path: Path) -> None:
    # No installed pack -> the custom-shaped secret is NOT flagged.
    assert "CRED-PLAINTEXT" not in _scan_ids(tmp_path)


def test_default_scan_schema_version_unchanged(tmp_path: Path) -> None:
    # Feature D adds no scan-JSON field, so the schema version does NOT bump.
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    assert report.schema_version == "1.1"


def test_scan_with_installed_store_pack_flags_custom_secret(tmp_path: Path) -> None:
    home = tmp_path / "home"
    store = home / ".config" / "mcpscan" / "datapack.json"
    store.parent.mkdir(parents=True)
    store.write_text(datapack_to_json(_custom_pack()), encoding="utf-8")
    assert "CRED-PLAINTEXT" in _scan_ids(tmp_path, home=home)


def test_scan_with_corrupt_store_falls_back_to_builtin(tmp_path: Path) -> None:
    home = tmp_path / "home"
    store = home / ".config" / "mcpscan" / "datapack.json"
    store.parent.mkdir(parents=True)
    store.write_text("{corrupt pack", encoding="utf-8")
    # A corrupt store neither crashes the scan nor weakens it below the built-in.
    ids = _scan_ids(tmp_path, home=home)
    assert "CRED-PLAINTEXT" not in ids  # custom pattern not applied (fell back)


def test_scan_with_store_still_flags_builtin_secrets(tmp_path: Path) -> None:
    # An installed pack must still catch the built-in provider shapes it inherits.
    home = tmp_path / "home"
    store = home / ".config" / "mcpscan" / "datapack.json"
    store.parent.mkdir(parents=True)
    store.write_text(datapack_to_json(_custom_pack()), encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    fixture = json.dumps(
        {"mcpServers": {"svc": {"command": "node", "env": {"OPENAI_API_KEY": "sk-" + "B" * 30}}}}
    )
    (project / ".mcp.json").write_text(fixture, encoding="utf-8")
    report = scan(roots=[project], system="Linux", env={"HOME": str(home)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-PLAINTEXT" in ids


# --- pure helper ------------------------------------------------------------
def test_first_allowed_signer() -> None:
    text = (
        "# a comment\n\npackpub@example.com ssh-ed25519 AAAA\nother@example.com ssh-ed25519 BBBB\n"
    )
    assert first_allowed_signer(text) == "packpub@example.com"


def test_first_allowed_signer_empty() -> None:
    assert first_allowed_signer("# only comments\n\n") is None


# --- update-datapack CLI ----------------------------------------------------
def _signers_file(tmp_path: Path) -> Path:
    signers = tmp_path / "signers"
    signers.write_text("packpub@example.com ssh-ed25519 AAAAbogus\n", encoding="utf-8")
    return signers


def test_update_datapack_requires_flags(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["update-datapack"])
    assert rc == 2
    assert "requires --pack" in capsys.readouterr().err


def test_update_datapack_cannot_determine_signer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack = _write_pack(tmp_path, builtin_datapack())
    sig = tmp_path / "sig"
    sig.write_text("x", encoding="utf-8")
    signers = tmp_path / "signers"
    signers.write_text("# no principals here\n", encoding="utf-8")
    rc = main(
        [
            "update-datapack",
            "--pack",
            str(pack),
            "--signature",
            str(sig),
            "--allowed-signers",
            str(signers),
        ]
    )
    assert rc == 2
    assert "signer identity" in capsys.readouterr().err


def test_update_datapack_verify_fail_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    import mcpscan.datapack as datapack_mod

    monkeypatch.setattr(
        datapack_mod, "load_verified_datapack", lambda *a, **k: DataPackError("bad sig")
    )
    pack = _write_pack(tmp_path, builtin_datapack())
    sig = tmp_path / "sig"
    sig.write_text("x", encoding="utf-8")
    signers = _signers_file(tmp_path)
    rc = main(
        [
            "update-datapack",
            "--pack",
            str(pack),
            "--signature",
            str(sig),
            "--allowed-signers",
            str(signers),
        ]
    )
    assert rc == 1
    assert "refused" in capsys.readouterr().err
    # No store was written under the isolated HOME.
    store = datapack_store_path("Linux", {"HOME": str(Path.home())})
    assert store is not None and not Path(str(store)).exists()


def test_update_datapack_non_utf8_input_is_a_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A non-UTF-8 --allowed-signers file must produce a clean error, not an
    # unhandled UnicodeDecodeError traceback (UnicodeDecodeError is a ValueError,
    # not an OSError, so the read guard must catch it).
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    pack = _write_pack(tmp_path, builtin_datapack())
    sig = tmp_path / "sig"
    sig.write_text("x", encoding="utf-8")
    bad_signers = tmp_path / "signers.bin"
    bad_signers.write_bytes(b"\xff\xfe not valid utf-8\x00")
    rc = main(
        [
            "update-datapack",
            "--pack",
            str(pack),
            "--signature",
            str(sig),
            "--allowed-signers",
            str(bad_signers),
        ]
    )
    assert rc == 2
    assert "cannot read" in capsys.readouterr().err


def test_update_datapack_success_installs_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    import mcpscan.datapack as datapack_mod

    monkeypatch.setattr(datapack_mod, "load_verified_datapack", lambda *a, **k: _custom_pack())
    pack = _write_pack(tmp_path, _custom_pack())
    sig = tmp_path / "sig"
    sig.write_text("x", encoding="utf-8")
    signers = _signers_file(tmp_path)
    rc = main(
        [
            "update-datapack",
            "--pack",
            str(pack),
            "--signature",
            str(sig),
            "--allowed-signers",
            str(signers),
        ]
    )
    assert rc == 0
    assert "installed data-pack" in capsys.readouterr().err
    # The installed store (resolved exactly as the CLI does) parses back to the pack.
    store = datapack_store_path(platform.system(), dict(os.environ))
    assert store is not None
    assert load_local_datapack(Path(str(store))) == _custom_pack()


@_needs_crypto
def test_update_datapack_ed25519_end_to_end_then_scan_picks_it_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Full path: sign -> update-datapack verifies + installs -> a fresh scan uses it.
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    pack_path, sig, signers, _op = _sign_ed25519(tmp_path, _custom_pack())
    rc = main(
        [
            "update-datapack",
            "--pack",
            str(pack_path),
            "--signature",
            str(sig),
            "--allowed-signers",
            str(signers),
            "--scheme",
            "ed25519",
        ]
    )
    assert rc == 0
    # The scan must resolve the datapack store exactly as the CLI install did —
    # same OS + environment. Forcing system="Linux" here (as the default helper
    # does) would look for the POSIX store path while the install used the real
    # OS's location (%APPDATA% on Windows), so the pack would be missed.
    ids = _scan_ids(tmp_path, system=platform.system(), env=dict(os.environ))
    assert "CRED-PLAINTEXT" in ids


def test_shipped_example_datapack_parses_and_extends_builtin() -> None:
    # The example under examples/datapack/ must stay valid as the schema evolves.
    example = (
        Path(__file__).resolve().parent.parent / "examples" / "datapack" / "example-datapack.json"
    )
    pack = parse_datapack(example.read_text(encoding="utf-8"))
    assert isinstance(pack, DataPack)
    labels = {label for label, _ in pack.provider_patterns}
    assert "Acme deploy token" in labels  # the sample's extra pattern
    # It is a superset of the built-in catalog, never a replacement.
    assert set(builtin_datapack().provider_patterns) <= set(pack.provider_patterns)
