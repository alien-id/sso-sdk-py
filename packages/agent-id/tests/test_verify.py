"""Port of `packages/agent-id/tests/verify.test.ts`."""

from __future__ import annotations

import json
import os

import pytest
from conftest import (
    Ed25519Pair,
    b64url,
    build_token,
    canonical_json,
    fingerprint_pem,
    generate_ed25519,
    now_ms,
    random_hex,
    sign_ed25519_b64url,
)

from alien_sso_agent_id import (
    VerifyOptions,
    verify_agent_request,
    verify_agent_token,
)


@pytest.fixture(scope="module")
def keys() -> Ed25519Pair:
    return generate_ed25519()


# ─── happy path ───────────────────────────────────────────────────────────


def test_verifies_valid_token(keys: Ed25519Pair):
    token = build_token(keys)
    result = verify_agent_token(token)
    assert result.ok is True
    assert result.fingerprint == fingerprint_pem(keys.public_key_pem)
    assert result.public_key_pem == keys.public_key_pem
    assert result.owner is None
    assert isinstance(result.timestamp, int)
    assert isinstance(result.nonce, str)


def test_verifies_token_with_owner(keys: Ed25519Pair):
    token = build_token(keys, owner="alice.alien")
    result = verify_agent_token(token)
    assert result.ok is True
    assert result.owner == "alice.alien"


def test_verifies_token_with_owner_explicit_null(keys: Ed25519Pair):
    token = build_token(keys, owner=None)
    result = verify_agent_token(token)
    assert result.ok is True
    assert result.owner is None


# ─── encoding errors ──────────────────────────────────────────────────────


def test_rejects_non_base64_garbage():
    result = verify_agent_token("!!!not-valid!!!")
    assert result.ok is False
    assert result.error == "Invalid token encoding"


def test_rejects_base64_that_is_not_json():
    token = b64url(b"not json")
    result = verify_agent_token(token)
    assert result.ok is False
    assert result.error == "Invalid token encoding"


# ─── version check ────────────────────────────────────────────────────────


def test_rejects_version_zero(keys: Ed25519Pair):
    result = verify_agent_token(build_token(keys, v=0))
    assert result.ok is False
    assert "Unsupported token version" in result.error


def test_rejects_version_two(keys: Ed25519Pair):
    result = verify_agent_token(build_token(keys, v=2))
    assert result.ok is False
    assert "Unsupported token version" in result.error


def test_rejects_missing_version(keys: Ed25519Pair):
    payload = {
        "fingerprint": fingerprint_pem(keys.public_key_pem),
        "publicKeyPem": keys.public_key_pem,
        "timestamp": now_ms(),
        "nonce": random_hex(16),
        "sig": "placeholder",
    }
    token = b64url(json.dumps(payload).encode("utf-8"))
    result = verify_agent_token(token)
    assert result.ok is False
    assert "Unsupported token version" in result.error


# ─── missing or invalid fields ────────────────────────────────────────────


def _payload_token(payload: dict) -> str:
    return b64url(json.dumps(payload).encode("utf-8"))


def test_rejects_missing_sig(keys: Ed25519Pair):
    token = _payload_token({
        "v": 1,
        "fingerprint": fingerprint_pem(keys.public_key_pem),
        "publicKeyPem": keys.public_key_pem,
        "timestamp": now_ms(),
        "nonce": random_hex(16),
    })
    result = verify_agent_token(token)
    assert result.ok is False
    assert result.error == "Missing or invalid field: sig"


def test_rejects_missing_fingerprint(keys: Ed25519Pair):
    token = _payload_token({
        "v": 1,
        "sig": "abc",
        "publicKeyPem": keys.public_key_pem,
        "timestamp": now_ms(),
        "nonce": random_hex(16),
    })
    result = verify_agent_token(token)
    assert result.error == "Missing or invalid field: fingerprint"


def test_rejects_missing_public_key(keys: Ed25519Pair):
    token = _payload_token({
        "v": 1,
        "sig": "abc",
        "fingerprint": "abc",
        "timestamp": now_ms(),
        "nonce": random_hex(16),
    })
    result = verify_agent_token(token)
    assert result.error == "Missing or invalid field: publicKeyPem"


def test_rejects_missing_timestamp(keys: Ed25519Pair):
    token = _payload_token({
        "v": 1,
        "sig": "abc",
        "fingerprint": "abc",
        "publicKeyPem": keys.public_key_pem,
        "nonce": random_hex(16),
    })
    result = verify_agent_token(token)
    assert result.error == "Missing or invalid field: timestamp"


def test_rejects_non_finite_timestamp(keys: Ed25519Pair):
    # Mirroring the JS test: JS Infinity → null when JSON.stringify'd. Python's
    # json module dumps math.inf as "Infinity" (non-standard JSON), so to match
    # the JS-on-the-wire behavior we encode null.
    token = _payload_token({
        "v": 1,
        "sig": "abc",
        "fingerprint": "abc",
        "publicKeyPem": keys.public_key_pem,
        "timestamp": None,
        "nonce": random_hex(16),
    })
    result = verify_agent_token(token)
    assert result.error == "Missing or invalid field: timestamp"


def test_rejects_missing_nonce(keys: Ed25519Pair):
    token = _payload_token({
        "v": 1,
        "sig": "abc",
        "fingerprint": "abc",
        "publicKeyPem": keys.public_key_pem,
        "timestamp": now_ms(),
    })
    result = verify_agent_token(token)
    assert result.error == "Missing or invalid field: nonce"


def test_rejects_owner_that_is_a_number(keys: Ed25519Pair):
    token = _payload_token({
        "v": 1,
        "sig": "abc",
        "fingerprint": "abc",
        "publicKeyPem": keys.public_key_pem,
        "timestamp": now_ms(),
        "nonce": random_hex(16),
        "owner": 42,
    })
    result = verify_agent_token(token)
    assert result.ok is False
    assert result.error == "Invalid field: owner"


# ─── expiry and clock skew ────────────────────────────────────────────────


def test_rejects_expired_token(keys: Ed25519Pair):
    token = build_token(keys, timestamp=now_ms() - 6 * 60 * 1000)
    result = verify_agent_token(token)
    assert result.ok is False
    assert "Token expired" in result.error


def test_accepts_token_within_max_age(keys: Ed25519Pair):
    token = build_token(keys, timestamp=now_ms() - 4 * 60 * 1000)
    assert verify_agent_token(token).ok is True


def test_accepts_slightly_future_dated_within_skew(keys: Ed25519Pair):
    token = build_token(keys, timestamp=now_ms() + 20 * 1000)
    assert verify_agent_token(token).ok is True


def test_rejects_future_dated_beyond_skew(keys: Ed25519Pair):
    token = build_token(keys, timestamp=now_ms() + 60 * 1000)
    result = verify_agent_token(token)
    assert result.ok is False
    assert "Token expired" in result.error


def test_respects_custom_max_age(keys: Ed25519Pair):
    token = build_token(keys, timestamp=now_ms() - 2000)
    result = verify_agent_token(token, VerifyOptions(max_age_ms=1000))
    assert result.ok is False


def test_respects_custom_clock_skew(keys: Ed25519Pair):
    token = build_token(keys, timestamp=now_ms() + 5000)
    result = verify_agent_token(token, VerifyOptions(clock_skew_ms=10_000))
    assert result.ok is True


# ─── fingerprint verification ─────────────────────────────────────────────


def test_rejects_tampered_fingerprint(keys: Ed25519Pair):
    token = build_token(keys, fingerprint="deadbeef" * 8)
    result = verify_agent_token(token)
    assert result.error == "Fingerprint does not match public key"


def test_rejects_invalid_public_key(keys: Ed25519Pair):
    token = _payload_token({
        "v": 1,
        "sig": "abc",
        "fingerprint": "abc",
        "publicKeyPem": "not-a-pem",
        "timestamp": now_ms(),
        "nonce": random_hex(16),
    })
    result = verify_agent_token(token)
    assert result.error == "Invalid public key in token"


# ─── signature verification ───────────────────────────────────────────────


def test_rejects_invalid_signature(keys: Ed25519Pair):
    token = build_token(
        keys,
        skip_sign=True,
        override_sig=b64url(os.urandom(64)),
    )
    result = verify_agent_token(token)
    assert result.error == "Signature verification failed"


def test_rejects_token_signed_by_different_key(keys: Ed25519Pair):
    other = generate_ed25519()
    fp = fingerprint_pem(keys.public_key_pem)
    payload = {
        "v": 1,
        "fingerprint": fp,
        "publicKeyPem": keys.public_key_pem,
        "timestamp": now_ms(),
        "nonce": random_hex(16),
    }
    payload["sig"] = sign_ed25519_b64url(canonical_json(payload), other.private_key_pem)
    token = b64url(json.dumps(payload).encode("utf-8"))
    result = verify_agent_token(token)
    assert result.error == "Signature verification failed"


# ─── verify_agent_request ─────────────────────────────────────────────────


def test_extracts_and_verifies_from_authorization_header(keys: Ed25519Pair):
    token = build_token(keys)
    req = {"headers": {"authorization": f"AgentID {token}"}}
    result = verify_agent_request(req)
    assert result.ok is True


def test_request_rejects_missing_authorization():
    req = {"headers": {}}
    result = verify_agent_request(req)
    assert result.ok is False
    assert result.error == "Missing header: Authorization: AgentID <token>"


def test_request_rejects_wrong_scheme():
    req = {"headers": {"authorization": "Bearer some-token"}}
    result = verify_agent_request(req)
    assert result.error == "Missing header: Authorization: AgentID <token>"


def test_request_handles_extra_whitespace(keys: Ed25519Pair):
    token = build_token(keys)
    req = {"headers": {"authorization": f"AgentID   {token}  "}}
    result = verify_agent_request(req)
    assert result.ok is True


def test_request_passes_options(keys: Ed25519Pair):
    token = build_token(keys, timestamp=now_ms() - 2000)
    req = {"headers": {"authorization": f"AgentID {token}"}}
    result = verify_agent_request(req, VerifyOptions(max_age_ms=1000))
    assert result.ok is False
