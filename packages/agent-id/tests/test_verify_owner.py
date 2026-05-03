"""Port of `packages/agent-id/tests/verify-owner.test.ts`."""

from __future__ import annotations

import json
import time

from conftest import (
    b64url,
    build_full_chain_token,
    fingerprint_pem,
    generate_ed25519,
    generate_rsa,
    now_ms,
    random_hex,
    sign_ed25519_b64url,
    sign_ed25519_hex,
)

from alien_sso_agent_id import (
    VerifyOwnerOptions,
    verify_agent_request_with_owner,
    verify_agent_token_with_owner,
)


# ─── happy path ───────────────────────────────────────────────────────────


def test_verifies_full_chain_without_proof():
    b = build_full_chain_token()
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.ok is True
    assert result.fingerprint == b.fp
    assert result.owner == b.owner
    assert result.owner_verified is True
    assert result.owner_proof_verified is False
    assert result.issuer == "https://sso.alien-api.com"


def test_verifies_full_chain_with_owner_session_proof():
    agent_keys = generate_ed25519()
    proof_keys = generate_ed25519()
    owner = "00000003010000000000539c741e0df8"
    seed = random_hex(16)
    sess_sig = sign_ed25519_hex(f"{owner}{seed}", proof_keys.private_key_pem)
    proof = {
        "sessionAddress": owner,
        "sessionSignature": sess_sig,
        "sessionSignatureSeed": seed,
        "sessionPublicKey": proof_keys.public_key_hex,
        "providerAddress": "test-provider",
        "signatureVerifiedAt": int(time.time()),
    }
    b = build_full_chain_token(agent_keys=agent_keys, owner=owner, owner_session_proof=proof)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.ok is True
    assert result.owner_verified is True
    assert result.owner_proof_verified is True


# ─── missing fields ───────────────────────────────────────────────────────


def test_rejects_missing_owner_binding():
    b = build_full_chain_token(omit_owner_binding=True)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.ok is False
    assert result.error == "Missing field: ownerBinding"


def test_rejects_missing_id_token():
    b = build_full_chain_token(omit_id_token=True)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "Missing field: idToken"


def test_rejects_missing_owner():
    b = build_full_chain_token(omit_owner=True)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "Token has no owner to verify"


# ─── owner binding verification ───────────────────────────────────────────


def test_rejects_tampered_payload_hash():
    agent_keys = generate_ed25519()
    rsa = generate_rsa()
    b = build_full_chain_token(agent_keys=agent_keys, rsa=rsa)
    # Tamper with the payload hash — proof fields are outside the agent-token signature
    parsed = json.loads(_b64url_decode_str(b.token_b64))
    parsed["ownerBinding"]["payloadHash"] = "deadbeef" * 8
    tampered = b64url(json.dumps(parsed).encode("utf-8"))
    result = verify_agent_token_with_owner(tampered, VerifyOwnerOptions(jwks=b.jwks))
    assert result.ok is False
    assert result.error == "Owner binding payload hash mismatch"


def test_rejects_binding_signed_by_different_key():
    agent_keys = generate_ed25519()
    other = generate_ed25519()
    b = build_full_chain_token(
        agent_keys=agent_keys,
        binding_signature_override=sign_ed25519_b64url("whatever", other.private_key_pem),
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "Owner binding signature verification failed"


def test_rejects_binding_with_wrong_agent_fingerprint():
    other = generate_ed25519()
    b = build_full_chain_token(
        binding_payload_overrides={
            "agentInstance": {
                "hostname": "test-host",
                "publicKeyFingerprint": fingerprint_pem(other.public_key_pem),
                "publicKeyPem": other.public_key_pem,
            }
        }
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "Owner binding agent fingerprint mismatch"


def test_rejects_binding_with_wrong_owner_session_sub():
    b = build_full_chain_token(
        binding_payload_overrides={"ownerSessionSub": "wrong-owner"},
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "Owner binding ownerSessionSub mismatch"


# ─── id_token verification ────────────────────────────────────────────────


def test_rejects_when_id_token_hash_does_not_match_binding():
    b = build_full_chain_token(id_token_hash_override="deadbeef" * 8)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "id_token hash does not match owner binding"


def test_rejects_id_token_signed_by_wrong_rsa_key():
    rsa1 = generate_rsa()
    rsa2 = generate_rsa()
    b = build_full_chain_token(rsa=rsa1, rsa_kid="kid1")
    jwks = {"keys": [{**rsa2.jwk, "kid": "kid1", "use": "sig", "alg": "RS256", "kty": "RSA"}]}
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=jwks))
    assert result.error == "id_token signature verification failed"


def test_rejects_when_no_jwks_key_matches_kid():
    b = build_full_chain_token(rsa_kid="kid-a")
    jwks = {"keys": [{"kty": "RSA", "kid": "kid-b", "use": "sig"}]}
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=jwks))
    assert result.ok is False
    assert "No matching JWKS key" in result.error


def test_rejects_when_id_token_sub_does_not_match_owner():
    b = build_full_chain_token(id_token_payload_overrides={"sub": "different-human"})
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "id_token sub does not match token owner"


def test_rejects_jwks_key_matching_kid_but_missing_n_e():
    b = build_full_chain_token(rsa_kid="kid-incomplete")
    jwks = {"keys": [{"kty": "RSA", "kid": "kid-incomplete", "use": "sig", "alg": "RS256"}]}
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=jwks))
    assert result.ok is False
    assert result.error == "Invalid JWKS key: missing required RSA fields (n, e)"


def test_accepts_expired_id_token_signature_only_check():
    b = build_full_chain_token(
        id_token_payload_overrides={"exp": int(time.time()) - 3600},
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.ok is True


# ─── owner session proof ──────────────────────────────────────────────────


def test_rejects_proof_with_wrong_session_address():
    proof_keys = generate_ed25519()
    wrong_owner = "wrong-address"
    seed = random_hex(16)
    session_sig = sign_ed25519_hex(f"{wrong_owner}{seed}", proof_keys.private_key_pem)
    b = build_full_chain_token(
        owner_session_proof={
            "sessionAddress": wrong_owner,
            "sessionSignature": session_sig,
            "sessionSignatureSeed": seed,
            "sessionPublicKey": proof_keys.public_key_hex,
        }
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "Owner session proof address mismatch"


def test_rejects_proof_with_invalid_signature():
    proof_keys = generate_ed25519()
    other = generate_ed25519()
    owner = "00000003010000000000539c741e0df8"
    seed = random_hex(16)
    session_sig = sign_ed25519_hex(f"{owner}{seed}", other.private_key_pem)
    b = build_full_chain_token(
        owner=owner,
        owner_session_proof={
            "sessionAddress": owner,
            "sessionSignature": session_sig,
            "sessionSignatureSeed": seed,
            "sessionPublicKey": proof_keys.public_key_hex,  # doesn't match signer
        },
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "Owner session proof signature failed"


def test_rejects_proof_with_incomplete_fields():
    b = build_full_chain_token(
        owner_session_proof={
            "sessionAddress": "00000003010000000000539c741e0df8",
        }
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks))
    assert result.error == "Incomplete owner session proof fields"


# ─── verify_agent_request_with_owner ──────────────────────────────────────


def test_request_extracts_and_verifies():
    b = build_full_chain_token()
    req = {"headers": {"authorization": f"AgentID {b.token_b64}"}}
    result = verify_agent_request_with_owner(req, VerifyOwnerOptions(jwks=b.jwks))
    assert result.ok is True
    assert result.owner == b.owner
    assert result.owner_verified is True


def test_request_rejects_missing_authorization():
    b = build_full_chain_token()
    req = {"headers": {}}
    result = verify_agent_request_with_owner(req, VerifyOwnerOptions(jwks=b.jwks))
    assert result.ok is False
    assert result.error == "Missing header: Authorization: AgentID <token>"


# ─── helpers ──────────────────────────────────────────────────────────────


def _b64url_decode_str(s: str) -> str:
    import base64
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8")
