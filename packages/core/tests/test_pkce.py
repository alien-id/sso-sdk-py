"""Port of `packages/core/tests/unit/client.test.ts` — the PKCE helpers."""

from __future__ import annotations

import re

from alien_sso._pkce import generate_code_challenge, generate_code_verifier

_BASE64URL = re.compile(r"^[A-Za-z0-9\-_]+$")


def test_code_verifier_is_non_empty_base64url():
    v = generate_code_verifier()
    assert isinstance(v, str)
    assert v
    assert _BASE64URL.match(v)


def test_code_verifier_is_unique():
    assert generate_code_verifier() != generate_code_verifier()


def test_code_verifier_length_within_rfc7636_window():
    # RFC 7636 §4.1: code_verifier "with a minimum length of 43 characters
    # and a maximum length of 128 characters."
    v = generate_code_verifier()
    assert 43 <= len(v) <= 128


def test_code_verifier_default_meets_256_bit_entropy_floor():
    # RFC 7636 §7.1 RECOMMENDED: "256 bits of entropy". Default = 32 random
    # octets ⇒ 43-char base64url verifier (32 bytes * 8 = 256 bits).
    v = generate_code_verifier()
    assert len(v) == 43


def test_code_challenge_is_43_char_base64url():
    challenge = generate_code_challenge("test-verifier")
    assert _BASE64URL.match(challenge)
    assert len(challenge) == 43  # SHA-256 → 32 bytes → 43 base64url chars


def test_code_challenge_is_deterministic():
    assert generate_code_challenge("same") == generate_code_challenge("same")


def test_code_challenge_changes_with_verifier():
    assert generate_code_challenge("a") != generate_code_challenge("b")
