"""Port of `packages/agent-id/tests/verify-owner.test.ts`."""

from __future__ import annotations

import json
import time

from conftest import (
    b64url,
    build_full_chain_token,
    ed25519_thumbprint,
    fingerprint_pem,
    generate_ed25519,
    generate_rsa,
    sign_ed25519_b64url,
)

from alien_sso_agent_id import (
    VerifyOwnerOptions,
    verify_agent_request_with_owner,
    verify_agent_token_with_owner,
)


# ─── happy path ───────────────────────────────────────────────────────────


def test_verifies_full_chain():
    b = build_full_chain_token()
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is True
    assert result.fingerprint == b.fp
    assert result.owner == b.owner
    assert result.owner_verified is True
    assert result.issuer == "https://sso.alien-api.com"


# ─── missing fields ───────────────────────────────────────────────────────


def test_rejects_missing_owner_binding():
    b = build_full_chain_token(omit_owner_binding=True)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert result.error == "Missing field: ownerBinding"


def test_rejects_missing_id_token():
    b = build_full_chain_token(omit_id_token=True)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.error == "Missing field: idToken"


def test_rejects_missing_owner():
    b = build_full_chain_token(omit_owner=True)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
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
    result = verify_agent_token_with_owner(tampered, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert result.error == "Owner binding payload hash mismatch"


def test_rejects_binding_signed_by_different_key():
    agent_keys = generate_ed25519()
    other = generate_ed25519()
    b = build_full_chain_token(
        agent_keys=agent_keys,
        binding_signature_override=sign_ed25519_b64url("whatever", other.private_key_pem),
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
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
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.error == "Owner binding agent fingerprint mismatch"


def test_rejects_binding_with_wrong_owner_session_sub():
    b = build_full_chain_token(
        binding_payload_overrides={"ownerSessionSub": "wrong-owner"},
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.error == "Owner binding ownerSessionSub mismatch"


# ─── id_token verification ────────────────────────────────────────────────


def test_rejects_when_id_token_hash_does_not_match_binding():
    b = build_full_chain_token(id_token_hash_override="deadbeef" * 8)
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.error == "id_token hash does not match owner binding"


def test_rejects_id_token_signed_by_wrong_rsa_key():
    rsa1 = generate_rsa()
    rsa2 = generate_rsa()
    b = build_full_chain_token(rsa=rsa1, rsa_kid="kid1")
    jwks = {"keys": [{**rsa2.jwk, "kid": "kid1", "use": "sig", "alg": "RS256", "kty": "RSA"}]}
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.error == "id_token signature verification failed"


def test_rejects_when_no_jwks_key_matches_kid():
    b = build_full_chain_token(rsa_kid="kid-a")
    jwks = {"keys": [{"kty": "RSA", "kid": "kid-b", "use": "sig"}]}
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert "No matching JWKS key" in result.error


def test_rejects_when_id_token_sub_does_not_match_owner():
    b = build_full_chain_token(id_token_payload_overrides={"sub": "different-human"})
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.error == "id_token sub does not match token owner"


def test_rejects_jwks_key_with_non_rs256_alg():
    # RFC 7515 §10.7: implementations MUST ensure the algorithm encoded
    # in the signature matches the JWK's declared `alg`. A JWK that pins
    # `alg: "PS256"` MUST NOT be used to verify an RS256 signature, even
    # if the underlying RSA bytes would round-trip.
    b = build_full_chain_token(rsa_kid="kid-ps256")
    jwks = {
        "keys": [
            {**b.rsa.jwk, "kty": "RSA", "kid": "kid-ps256", "use": "sig", "alg": "PS256"}
        ]
    }
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert "JWKS key" in result.error  # any message about the alg mismatch is fine


def test_accepts_jwks_key_without_alg_member():
    # RFC 7517 §4.4: `alg` is OPTIONAL on a JWK. When absent, our lookup
    # remains permissive — the JWT's own header alg is the source of truth.
    b = build_full_chain_token(rsa_kid="kid-no-alg")
    jwks = {
        "keys": [
            # Drop alg from the published JWK.
            {k: v for k, v in {**b.rsa.jwk, "kty": "RSA", "kid": "kid-no-alg", "use": "sig"}.items() if k != "alg"}
        ]
    }
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is True


def test_rejects_jwks_key_matching_kid_but_missing_n_e():
    b = build_full_chain_token(rsa_kid="kid-incomplete")
    jwks = {"keys": [{"kty": "RSA", "kid": "kid-incomplete", "use": "sig", "alg": "RS256"}]}
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert result.error == "Invalid JWKS key: missing required RSA fields (n, e)"


def test_rejects_expired_id_token():
    # RFC 7519 §4.1.4 / §7.2: "the current date/time MUST be before the
    # expiration date/time listed in the 'exp' claim."
    b = build_full_chain_token(
        id_token_payload_overrides={"exp": int(time.time()) - 3600},
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert result.error == "id_token expired"


def test_rejects_id_token_with_future_nbf():
    # RFC 7519 §4.1.5: "the current date/time MUST be after or equal to
    # the not-before date/time listed in the 'nbf' claim."
    b = build_full_chain_token(
        id_token_payload_overrides={"nbf": int(time.time()) + 3600},
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert result.error == "id_token not yet valid"


def test_accepts_id_token_within_clock_skew_of_exp():
    # exp just barely in the past, but within the 30s default skew → accept.
    b = build_full_chain_token(
        id_token_payload_overrides={"exp": int(time.time()) - 5},
    )
    result = verify_agent_token_with_owner(b.token_b64, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is True


def test_rejects_id_token_with_wrong_audience():
    # RFC 7519 §4.1.3: "If the principal processing the claim does not
    # identify itself with a value in the 'aud' claim when this claim is
    # present, then the JWT MUST be rejected."
    b = build_full_chain_token(
        id_token_payload_overrides={"aud": "different-rp"},
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token aud does not match expected audience"


def test_accepts_id_token_with_aud_list_containing_expected():
    # RFC 7519 §4.1.3 also allows aud to be an array; principal must be
    # identified by *one* of the values. OIDC §3.1.3.7 step 3 also requires
    # extra audiences to be in the caller's trusted set.
    b = build_full_chain_token(
        id_token_payload_overrides={"aud": ["other-rp", "test-provider"]},
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(
            jwks=b.jwks,
            expected_issuer="https://sso.alien-api.com",
            expected_audience="test-provider",
            trusted_audiences=frozenset({"test-provider", "other-rp"}),
        ),
    )
    assert result.ok is True


def test_rejects_id_token_with_extra_untrusted_audience():
    # OIDC §3.1.3.7 step 3: "MUST be rejected ... if it contains additional
    # audiences not trusted by the Client." Default trust set = expected.
    b = build_full_chain_token(
        id_token_payload_overrides={
            "aud": ["test-provider", "attacker-rp"],
            "azp": "test-provider",
        },
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert "untrusted audience" in result.error


def test_accepts_id_token_with_extra_audience_when_caller_trusts_it():
    b = build_full_chain_token(
        id_token_payload_overrides={
            "aud": ["test-provider", "ally-rp"],
            "azp": "test-provider",
        },
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(
            jwks=b.jwks,
            expected_issuer="https://sso.alien-api.com",
            expected_audience="test-provider",
            trusted_audiences=frozenset({"test-provider", "ally-rp"}),
        ),
    )
    assert result.ok is True


def test_accepts_id_token_when_expected_audience_is_a_list():
    # Caller passes a list of acceptable audiences — match if the token's
    # aud (string or list) intersects the expected set.
    b = build_full_chain_token(
        id_token_payload_overrides={"aud": "test-provider"},
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience=["other-rp", "test-provider"]),
    )
    assert result.ok is True


def test_verify_owner_options_requires_expected_audience_only():
    # RFC 7519 §4.1.3 / OIDC §3.1.3.7: `expected_audience` MUST be
    # caller-supplied — it is the Client's own ``client_id`` and the
    # library cannot guess it. `expected_issuer` is optional; the agent-id
    # package is single-tenant against Alien SSO and falls back to
    # ``DEFAULT_SSO_BASE_URL`` when the caller omits it.
    import pytest

    with pytest.raises(TypeError):
        VerifyOwnerOptions(jwks={"keys": []})  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        VerifyOwnerOptions(  # type: ignore[call-arg]
            jwks={"keys": []}, expected_issuer="x"
        )
    # Audience-only is valid: issuer defaults to DEFAULT_SSO_BASE_URL.
    opts = VerifyOwnerOptions(jwks={"keys": []}, expected_audience="y")
    assert opts.expected_issuer is None


def test_rejects_id_token_with_wrong_issuer():
    # RFC 7519 §4.1.1 / RFC 9068 §5: when an expected issuer is configured,
    # the iss claim MUST exactly match the configured value.
    b = build_full_chain_token(
        id_token_payload_overrides={"iss": "https://attacker.example.com"},
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token iss does not match expected issuer"


def test_default_expected_issuer_is_alien_sso():
    # The library is single-tenant against Alien SSO; when the caller
    # omits `expected_issuer`, the verifier pins to the production
    # endpoint. A token whose iss matches the default verifies cleanly.
    b = build_full_chain_token()  # default iss = https://sso.alien-api.com
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_audience="test-provider"),
    )
    assert result.ok is True


def test_default_expected_issuer_rejects_non_default_iss():
    # Mirror of `test_rejects_id_token_with_wrong_issuer`, but exercising
    # the default path: an id_token from a non-default AS must fail when
    # the caller did not opt in via `expected_issuer`.
    b = build_full_chain_token(
        id_token_payload_overrides={"iss": "https://staging.alien-api.com"},
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token iss does not match expected issuer"


def test_rejects_id_token_with_non_numeric_iat():
    # RFC 7519 §4.1.6: "Its value MUST be a number containing a NumericDate
    # value." A string `iat` is malformed and MUST be rejected.
    b = build_full_chain_token(
        id_token_payload_overrides={"iat": "not-a-number"},
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token iat must be a NumericDate"


def test_accepts_id_token_with_numeric_iat():
    b = build_full_chain_token(id_token_payload_overrides={"iat": int(time.time())})
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is True


def test_rejects_id_token_with_boolean_iat():
    # bool is an int subclass in Python; the NumericDate guard MUST exclude it.
    b = build_full_chain_token(id_token_payload_overrides={"iat": True})
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token iat must be a NumericDate"


def test_rejects_id_token_with_missing_exp():
    # RFC 7519 §4.1.4 says exp MAY be present, but RFC 9068 §2.2 makes it
    # REQUIRED for ATs and OIDC §2 makes it REQUIRED for id_tokens. Treat
    # absent exp as a hard fail to avoid silently accepting eternal tokens.
    b = build_full_chain_token(id_token_payload_overrides={"exp": None})
    # Override path: build the payload, then strip exp via override hook.
    # The build helper merges via dict.update — None will overwrite. Convert
    # to omitting by manual rebuild:
    import json
    from conftest import b64url, sign_rs256
    payload = {
        "iss": "https://sso.alien-api.com",
        "sub": b.owner,
        "aud": "test-provider",
        "iat": int(time.time()),
    }
    h = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "test-kid"}).encode())
    p = b64url(json.dumps(payload).encode())
    sig = sign_rs256(f"{h}.{p}".encode("ascii"), b.rsa.private_key)
    no_exp_id_token = f"{h}.{p}.{b64url(sig)}"
    b2 = build_full_chain_token(
        agent_keys=b.agent_keys,
        rsa=b.rsa,
        owner=b.owner,
        id_token_override=no_exp_id_token,
    )
    result = verify_agent_token_with_owner(b2.token_b64, VerifyOwnerOptions(jwks=b2.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert result.error == "id_token missing exp"


# ─── cnf.jkt PoP binding (RFC 7800 §3.1, RFC 9449 §6.1) ──────────────────


def test_rejects_id_token_missing_cnf_jkt():
    # Without `cnf.jkt` the id_token is not bound to the presenting
    # agent — an attacker who steals an id_token could replay it across
    # a fabricated binding and proof bundle.
    b = build_full_chain_token(omit_cnf=True)
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token missing cnf.jkt"


def test_rejects_id_token_whose_cnf_jkt_does_not_bind_to_agent_key():
    # RFC 7800 §3.1: cnf.jkt MUST be the RFC 7638 thumbprint of the
    # presenter's key. A non-matching thumbprint is a binding violation
    # even if every other claim verifies.
    other_keys = generate_ed25519()
    b = build_full_chain_token(
        id_token_payload_overrides={"cnf": {"jkt": ed25519_thumbprint(other_keys.public_key_pem)}},
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token cnf.jkt does not bind to agent key"


# ─── encrypted ID Token policy (OIDC §3.1.3.7 / RFC 7516) ────────────────


def test_rejects_jwe_compact_serialization():
    # RFC 7516 §9: JWEs have five segments separated by four periods. We do
    # not implement decryption — surface the policy as an explicit error
    # rather than a parse failure (current silent rejection is confusing).
    b = build_full_chain_token()
    fake_jwe = "a.b.c.d.e"  # five-segment compact serialization
    b2 = build_full_chain_token(
        agent_keys=b.agent_keys,
        rsa=b.rsa,
        owner=b.owner,
        id_token_override=fake_jwe,
    )
    result = verify_agent_token_with_owner(
        b2.token_b64,
        VerifyOwnerOptions(jwks=b2.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert "Encrypted ID Token" in result.error


def test_rejects_jws_with_enc_header():
    # RFC 7516 §4.1.2: `enc` is mandatory in JWE protected header. A JWS
    # carrying `enc` is malformed / mis-routed — reject with the same
    # explicit policy error.
    from conftest import b64url, sign_rs256

    b = build_full_chain_token()
    payload = {
        "iss": "https://sso.alien-api.com",
        "sub": b.owner,
        "aud": "test-provider",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    header = {"alg": "RSA-OAEP", "enc": "A256GCM", "typ": "JWT", "kid": "test-kid"}
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(payload).encode())
    sig = sign_rs256(f"{h}.{p}".encode("ascii"), b.rsa.private_key)
    enc_token = f"{h}.{p}.{b64url(sig)}"
    b2 = build_full_chain_token(
        agent_keys=b.agent_keys,
        rsa=b.rsa,
        owner=b.owner,
        id_token_override=enc_token,
    )
    result = verify_agent_token_with_owner(
        b2.token_b64,
        VerifyOwnerOptions(jwks=b2.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert "Encrypted ID Token" in result.error


# ─── verify_agent_request_with_owner ──────────────────────────────────────


def test_request_extracts_and_verifies():
    b = build_full_chain_token()
    req = {"headers": {"authorization": f"AgentID {b.token_b64}"}}
    result = verify_agent_request_with_owner(req, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is True
    assert result.owner == b.owner
    assert result.owner_verified is True


def test_request_rejects_missing_authorization():
    b = build_full_chain_token()
    req = {"headers": {}}
    result = verify_agent_request_with_owner(req, VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"))
    assert result.ok is False
    assert result.error == "Missing header: Authorization: AgentID <token>"


# ─── azp (OIDC Core §3.1.3.7.6 / .7) ──────────────────────────────────────


def test_accepts_id_token_multi_aud_with_matching_azp():
    # OIDC §3.1.3.7.7: when azp is present and aud has multiple values,
    # azp MUST equal the client_id (i.e., expected_audience). Caller
    # widens trusted_audiences (§3.1.3.7 step 3) to admit the second aud.
    b = build_full_chain_token(
        id_token_payload_overrides={
            "aud": ["test-provider", "other-rp"],
            "azp": "test-provider",
        },
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(
            jwks=b.jwks,
            expected_issuer="https://sso.alien-api.com",
            expected_audience="test-provider",
            trusted_audiences=frozenset({"test-provider", "other-rp"}),
        ),
    )
    assert result.ok is True


def test_rejects_id_token_multi_aud_with_mismatched_azp():
    b = build_full_chain_token(
        id_token_payload_overrides={
            "aud": ["test-provider", "other-rp"],
            "azp": "other-rp",
        },
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(
            jwks=b.jwks,
            expected_issuer="https://sso.alien-api.com",
            expected_audience="test-provider",
            trusted_audiences=frozenset({"test-provider", "other-rp"}),
        ),
    )
    assert result.ok is False
    assert result.error == "id_token azp does not match expected audience"


def test_rejects_id_token_with_azp_not_matching_client_id():
    # OIDC §3.1.3.7.6: when azp is present, client MUST verify it.
    b = build_full_chain_token(
        id_token_payload_overrides={
            "aud": "test-provider",
            "azp": "different-client",
        },
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token azp does not match expected audience"


def test_accepts_single_aud_without_azp():
    # azp absent + single matching aud → OIDC says no further check needed.
    b = build_full_chain_token(
        id_token_payload_overrides={"aud": "test-provider"},
    )
    result = verify_agent_token_with_owner(
        b.token_b64,
        VerifyOwnerOptions(jwks=b.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is True


# ─── crit header (RFC 7515 §4.1.11) ───────────────────────────────────────


def test_rejects_id_token_with_crit_header():
    # RFC 7515 §4.1.11: "If any of the listed extension Header Parameters
    # are not understood and supported by the recipient, then the JWS is
    # invalid." We support no extensions; any non-empty crit list is fatal.
    from conftest import b64url, sign_rs256

    b = build_full_chain_token()
    payload = {
        "iss": "https://sso.alien-api.com",
        "sub": b.owner,
        "aud": "test-provider",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": "test-kid", "crit": ["my-ext"], "my-ext": "v"}
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(payload).encode())
    sig = sign_rs256(f"{h}.{p}".encode("ascii"), b.rsa.private_key)
    crit_id_token = f"{h}.{p}.{b64url(sig)}"
    b2 = build_full_chain_token(
        agent_keys=b.agent_keys,
        rsa=b.rsa,
        owner=b.owner,
        id_token_override=crit_id_token,
    )
    result = verify_agent_token_with_owner(
        b2.token_b64,
        VerifyOwnerOptions(jwks=b2.jwks, expected_issuer="https://sso.alien-api.com", expected_audience="test-provider"),
    )
    assert result.ok is False
    assert result.error == "id_token contains unsupported crit header"


# ─── helpers ──────────────────────────────────────────────────────────────


def _b64url_decode_str(s: str) -> str:
    import base64
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8")
