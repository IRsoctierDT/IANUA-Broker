# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secret redaction (R1 / T-206 slice)."""

from __future__ import annotations

from mcpscan.redaction import fingerprint_secret, mask

RAW = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def test_mask_reveals_at_most_first2_last2() -> None:
    m = mask(RAW)
    assert m.startswith("sk")
    assert m.endswith("89")
    assert m.count("*") == len(RAW) - 4


def test_short_secret_is_fully_masked() -> None:
    assert mask("abcd") == "****"
    assert set(mask("xy")) == {"*"}


def test_fingerprint_never_contains_raw_value() -> None:
    fp = fingerprint_secret(RAW)
    assert RAW not in fp.masked
    assert RAW not in fp.sha256_8
    # Only first2/last2 of the raw may appear, never an internal run.
    assert "CDEFGH" not in fp.masked


def test_fingerprint_is_deterministic_and_truncated() -> None:
    fp1 = fingerprint_secret(RAW)
    fp2 = fingerprint_secret(RAW)
    assert fp1 == fp2
    assert len(fp1.sha256_8) == 8
    assert fp1.length == len(RAW)
