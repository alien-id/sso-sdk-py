"""RFC 9449 §4.3 DPoP request verifier — port of
`packages/agent-id/tests/verify-dpop.test.ts` from the JS SDK.

Each test pins one RFC-mandated rejection so future refactors of the
internals can't silently weaken the verifier.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from alien_sso_agent_id import verify_dpop_request
from alien_sso_agent_id.types import JWKS, VerifyDPoPOptions, VerifyDPoPSuccess, VerifyDPoPFailure


# ─── Test helpers ────────────────────────────────────────────────────────────

EXPECTED_ISSUER = "https://sso.alien-api.com"
EXPECTED_AUDIENCE = "test-resource"
RESOURCE_URL = "https://api.example.test/v1/whoami"


def _b64url(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _sha256_b64url(s: str) -> str:
    return _b64url(hashlib.sha256(s.encode("utf-8")).digest())


def _generate_ed25519() -> dict:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    x = _b64url(der[12:])
    return {
        "_priv": priv,
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
    }


def _generate_rsa() -> dict:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    n = pub.public_numbers().n
    e = pub.public_numbers().e
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    jwk = {"kty": "RSA", "n": _b64url(n_bytes), "e": _b64url(e_bytes)}
    return {"_priv": priv, "jwk": jwk}


def _jwk_thumbprint_okp(jwk: dict) -> str:
    canonical = f'{{"crv":"{jwk["crv"]}","kty":"{jwk["kty"]}","x":"{jwk["x"]}"}}'
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def _mint_access_token(
    *,
    rsa_pair: dict,
    kid: str,
    sub: str,
    agent_jkt: str,
    iss: str | None = None,
    aud: Any = None,
    iat: int | None = None,
    exp: int | None = None,
    payload_overrides: dict | None = None,
    header_overrides: dict | None = None,
) -> str:
    header = {"typ": "at+jwt", "alg": "RS256", "kid": kid}
    if header_overrides:
        header.update(header_overrides)
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": iss if iss is not None else EXPECTED_ISSUER,
        "sub": sub,
        # Mirror the SSO's `aud = [client_id, issuer]` shape so the
        # federated-audience default succeeds when callers don't pin
        # expected_audience. Tests that exercise scope-specific behavior
        # override this via the `aud` kwarg.
        "aud": aud if aud is not None else [EXPECTED_AUDIENCE, EXPECTED_ISSUER],
        "iat": iat if iat is not None else now,
        "exp": exp if exp is not None else now + 600,
        "cnf": {"jkt": agent_jkt},
    }
    if payload_overrides:
        for k, v in payload_overrides.items():
            if v is None and k in payload:
                # Explicit None drops the claim entirely (matches JS spread+undefined).
                del payload[k]
            else:
                payload[k] = v
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = rsa_pair["_priv"].sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def _normalize_htu(s: str) -> str:
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(s)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _mint_dpop_proof(
    *,
    agent: dict,
    htm: str,
    htu: str,
    access_token: str,
    iat: int | None = None,
    jti: str | None = None,
    payload_overrides: dict | None = None,
    header_overrides: dict | None = None,
) -> str:
    header: dict[str, Any] = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": agent["jwk"]}
    if header_overrides:
        for k, v in header_overrides.items():
            if v is None and k in header:
                del header[k]
            else:
                header[k] = v
    try:
        clean_htu = _normalize_htu(htu)
    except Exception:
        clean_htu = htu
    payload: dict[str, Any] = {
        "jti": jti if jti is not None else uuid.uuid4().hex,
        "htm": htm,
        "htu": clean_htu,
        "iat": iat if iat is not None else int(time.time()),
        "ath": _sha256_b64url(access_token),
    }
    if payload_overrides:
        for k, v in payload_overrides.items():
            if v is None and k in payload:
                del payload[k]
            else:
                payload[k] = v
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = agent["_priv"].sign(signing_input)
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def _build_request(
    *,
    method: str = "GET",
    url: str = RESOURCE_URL,
    sub: str = "00000003010000000000539c741e0df8",
    access_token_kwargs: dict | None = None,
    proof_kwargs: dict | None = None,
    auth_header: Any = ...,  # sentinel
    dpop_header: Any = ...,  # sentinel
    omit_auth: bool = False,
    omit_dpop: bool = False,
) -> dict:
    agent = _generate_ed25519()
    rsa_pair = _generate_rsa()
    kid = "sso-test-kid"
    agent_jkt = _jwk_thumbprint_okp(agent["jwk"])

    at_kwargs = {"rsa_pair": rsa_pair, "kid": kid, "sub": sub, "agent_jkt": agent_jkt}
    if access_token_kwargs:
        at_kwargs.update(access_token_kwargs)
    access_token = _mint_access_token(**at_kwargs)

    pf_kwargs = {"agent": agent, "htm": method, "htu": url, "access_token": access_token}
    if proof_kwargs:
        pf_kwargs.update(proof_kwargs)
    proof = _mint_dpop_proof(**pf_kwargs)

    jwks: JWKS = {
        "keys": [{**rsa_pair["jwk"], "kid": kid, "use": "sig", "alg": "RS256"}]
    }

    headers: dict[str, Any] = {}
    if not omit_auth:
        headers["authorization"] = auth_header if auth_header is not ... else f"DPoP {access_token}"
    if not omit_dpop:
        headers["dpop"] = dpop_header if dpop_header is not ... else proof

    return {
        "req": {"method": method, "url": url, "headers": headers},
        "access_token": access_token,
        "proof": proof,
        "agent": agent,
        "agent_jkt": agent_jkt,
        "rsa": rsa_pair,
        "kid": kid,
        "jwks": jwks,
        "sub": sub,
    }


def _expect_failure(result, code: str):
    assert not result.ok, f"expected failure {code!r}, got success: {result}"
    assert isinstance(result, VerifyDPoPFailure)
    assert result.code == code, f"expected code {code!r}, got {result.code!r}: {result.error}"


# ─── Tracer bullet: well-formed end-to-end happy path ────────────────────────


def test_verifies_well_formed_dpop_request_end_to_end():
    b = _build_request()
    result = verify_dpop_request(
        b["req"],
        VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER, expected_audience=EXPECTED_AUDIENCE),
    )
    assert result.ok, getattr(result, "error", None)
    assert isinstance(result, VerifyDPoPSuccess)
    assert result.sub == b["sub"]
    assert result.jkt == b["agent_jkt"]
    assert result.access_token_claims["iss"] == EXPECTED_ISSUER
    assert result.proof_claims["htm"] == "GET"


# ─── Step 1: header presence & uniqueness ────────────────────────────────────


def test_rejects_missing_authorization():
    b = _build_request(omit_auth=True)
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "missing_authorization",
    )


def test_rejects_duplicate_authorization_array():
    b = _build_request(omit_auth=True)
    b["req"]["headers"]["authorization"] = [
        f"DPoP {b['access_token']}",
        f"DPoP {b['access_token']}",
    ]
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "missing_authorization",
    )


def test_rejects_non_dpop_scheme():
    b = _build_request()
    b["req"]["headers"]["authorization"] = f"Bearer {b['access_token']}"
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "invalid_scheme",
    )


def test_accepts_dpop_scheme_case_insensitively():
    b = _build_request()
    b["req"]["headers"]["authorization"] = f"dpop {b['access_token']}"
    result = verify_dpop_request(
        b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)
    )
    assert result.ok


def test_rejects_missing_dpop_header():
    b = _build_request(omit_dpop=True)
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "missing_dpop",
    )


def test_rejects_duplicate_dpop_array():
    b = _build_request()
    b["req"]["headers"]["dpop"] = [b["proof"], b["proof"]]
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "missing_dpop",
    )


# ─── Step 2: well-formed JWS ─────────────────────────────────────────────────


def test_rejects_malformed_proof_jws():
    b = _build_request(dpop_header="not.a.jwt")
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "malformed_proof",
    )


# ─── Step 4: typ ─────────────────────────────────────────────────────────────


def test_rejects_proof_typ_not_dpop_jwt():
    b = _build_request(proof_kwargs={"header_overrides": {"typ": "jwt"}})
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "bad_proof_typ",
    )


# ─── Step 5: alg ─────────────────────────────────────────────────────────────


def test_rejects_proof_alg_not_eddsa():
    b = _build_request(proof_kwargs={"header_overrides": {"alg": "RS256"}})
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "bad_proof_alg",
    )


# ─── Step 6: jwk shape & private-member rejection ────────────────────────────


def test_rejects_proof_missing_jwk_header():
    # Hand-craft a proof without the jwk header so the verifier rejects
    # before signature verification.
    agent = _generate_ed25519()
    rsa_pair = _generate_rsa()
    kid = "k1"
    agent_jkt = _jwk_thumbprint_okp(agent["jwk"])
    access_token = _mint_access_token(rsa_pair=rsa_pair, kid=kid, sub="s", agent_jkt=agent_jkt)
    header_b64 = _b64url(
        json.dumps({"typ": "dpop+jwt", "alg": "EdDSA"}, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = _b64url(
        json.dumps(
            {
                "jti": uuid.uuid4().hex,
                "htm": "GET",
                "htu": RESOURCE_URL,
                "iat": int(time.time()),
                "ath": _sha256_b64url(access_token),
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = agent["_priv"].sign(signing_input)
    proof = f"{header_b64}.{payload_b64}.{_b64url(sig)}"
    jwks = {"keys": [{**rsa_pair["jwk"], "kid": kid, "use": "sig", "alg": "RS256"}]}
    _expect_failure(
        verify_dpop_request(
            {
                "method": "GET",
                "url": RESOURCE_URL,
                "headers": {"authorization": f"DPoP {access_token}", "dpop": proof},
            },
            VerifyDPoPOptions(jwks=jwks, expected_issuer=EXPECTED_ISSUER),
        ),
        "missing_proof_jwk",
    )


def test_rejects_proof_with_wrong_kty_or_crv():
    b = _build_request(
        proof_kwargs={"header_overrides": {"jwk": {"kty": "EC", "crv": "P-256", "x": "fake"}}}
    )
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "bad_proof_jwk",
    )


def test_rejects_proof_jwk_with_private_d():
    agent = _generate_ed25519()
    rsa_pair = _generate_rsa()
    kid = "k1"
    agent_jkt = _jwk_thumbprint_okp(agent["jwk"])
    access_token = _mint_access_token(rsa_pair=rsa_pair, kid=kid, sub="s", agent_jkt=agent_jkt)
    proof = _mint_dpop_proof(
        agent=agent,
        htm="GET",
        htu=RESOURCE_URL,
        access_token=access_token,
        header_overrides={"jwk": {**agent["jwk"], "d": "leaked-private-key"}},
    )
    jwks = {"keys": [{**rsa_pair["jwk"], "kid": kid, "use": "sig", "alg": "RS256"}]}
    _expect_failure(
        verify_dpop_request(
            {
                "method": "GET",
                "url": RESOURCE_URL,
                "headers": {"authorization": f"DPoP {access_token}", "dpop": proof},
            },
            VerifyDPoPOptions(jwks=jwks, expected_issuer=EXPECTED_ISSUER),
        ),
        "private_in_proof_jwk",
    )


# ─── Step 7: signature ───────────────────────────────────────────────────────


def test_rejects_proof_signed_by_different_key_than_jwk():
    real_agent = _generate_ed25519()
    attacker = _generate_ed25519()
    rsa_pair = _generate_rsa()
    kid = "k1"
    agent_jkt = _jwk_thumbprint_okp(real_agent["jwk"])
    access_token = _mint_access_token(rsa_pair=rsa_pair, kid=kid, sub="s", agent_jkt=agent_jkt)
    # Build the proof with real_agent's jwk in the header but signed by attacker.
    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": real_agent["jwk"]}
    payload = {
        "jti": uuid.uuid4().hex,
        "htm": "GET",
        "htu": RESOURCE_URL,
        "iat": int(time.time()),
        "ath": _sha256_b64url(access_token),
    }
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = attacker["_priv"].sign(signing_input)
    proof = f"{h_b64}.{p_b64}.{_b64url(sig)}"
    jwks = {"keys": [{**rsa_pair["jwk"], "kid": kid, "use": "sig", "alg": "RS256"}]}
    _expect_failure(
        verify_dpop_request(
            {
                "method": "GET",
                "url": RESOURCE_URL,
                "headers": {"authorization": f"DPoP {access_token}", "dpop": proof},
            },
            VerifyDPoPOptions(jwks=jwks, expected_issuer=EXPECTED_ISSUER),
        ),
        "bad_proof_signature",
    )


# ─── Step 8: htm ─────────────────────────────────────────────────────────────


def test_rejects_proof_htm_mismatch():
    b = _build_request(method="GET")
    b["req"]["method"] = "POST"
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "bad_proof_htm",
    )


# ─── Step 9: htu ─────────────────────────────────────────────────────────────


def test_rejects_proof_htu_mismatch():
    b = _build_request(proof_kwargs={"htu": "https://other.example.test/different/path"})
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "bad_proof_htu",
    )


def test_accepts_htu_with_query_or_fragment_stripped():
    b = _build_request(proof_kwargs={"htu": f"{RESOURCE_URL}?foo=bar#frag"})
    result = verify_dpop_request(
        b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)
    )
    assert result.ok, getattr(result, "error", None)


def test_accepts_htu_with_default_port_stripped():
    # WHATWG URL semantics: `https://h:443/p` normalizes to `https://h/p`.
    # The verifier must accept either side carrying the explicit default
    # port, matching `new URL(...).toString()` in the JS SDK.
    b = _build_request(
        url="https://api.example.test/v1/whoami",
        proof_kwargs={"htu": "https://api.example.test:443/v1/whoami"},
    )
    result = verify_dpop_request(
        b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)
    )
    assert result.ok, getattr(result, "error", None)


def test_accepts_htu_with_host_case_difference():
    # WHATWG lowercases the host. A request URL with mixed-case host must
    # normalize to the same htu the agent (which uses URL.toString()) signs.
    b = _build_request(
        url="https://API.example.test/v1/whoami",
        proof_kwargs={"htu": "https://api.example.test/v1/whoami"},
    )
    result = verify_dpop_request(
        b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)
    )
    assert result.ok, getattr(result, "error", None)


# ─── Step 11: iat freshness ──────────────────────────────────────────────────


def test_rejects_stale_proof():
    past = int(time.time()) - 600
    b = _build_request(proof_kwargs={"iat": past})
    _expect_failure(
        verify_dpop_request(
            b["req"],
            VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER, proof_max_age_sec=30),
        ),
        "stale_proof",
    )


def test_rejects_future_dated_proof():
    future = int(time.time()) + 600
    b = _build_request(proof_kwargs={"iat": future})
    _expect_failure(
        verify_dpop_request(
            b["req"],
            VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER, proof_max_age_sec=30),
        ),
        "future_proof",
    )


# ─── Step 12: jti replay ─────────────────────────────────────────────────────


def test_rejects_replayed_jti():
    b = _build_request()
    opts = VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)
    first = verify_dpop_request(b["req"], opts)
    assert first.ok
    second = verify_dpop_request(b["req"], opts)
    _expect_failure(second, "replayed_proof_jti")


def test_honors_caller_supplied_jti_store():
    seen: set[str] = set()

    class _Store:
        def has(self, jti: str) -> bool:
            return jti in seen

        def add(self, jti: str, iat: int) -> None:
            seen.add(jti)

    b = _build_request()
    opts = VerifyDPoPOptions(
        jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER, jti_store=_Store()
    )
    assert len(seen) == 0
    r1 = verify_dpop_request(b["req"], opts)
    assert r1.ok
    assert len(seen) == 1
    r2 = verify_dpop_request(b["req"], opts)
    _expect_failure(r2, "replayed_proof_jti")


# ─── RFC 9068 §4: access token claims ────────────────────────────────────────


def test_rejects_access_token_wrong_typ():
    b = _build_request(access_token_kwargs={"header_overrides": {"typ": "JWT"}})
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "bad_access_token_typ",
    )


def test_rejects_access_token_unknown_kid():
    b = _build_request()
    other = _generate_rsa()
    jwks = {"keys": [{**other["jwk"], "kid": "unrelated", "use": "sig", "alg": "RS256"}]}
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=jwks, expected_issuer=EXPECTED_ISSUER)),
        "unknown_access_token_kid",
    )


def test_rejects_access_token_bad_rsa_signature():
    agent = _generate_ed25519()
    real_rsa = _generate_rsa()
    fake_rsa = _generate_rsa()
    kid = "k1"
    agent_jkt = _jwk_thumbprint_okp(agent["jwk"])
    access_token = _mint_access_token(rsa_pair=real_rsa, kid=kid, sub="s", agent_jkt=agent_jkt)
    proof = _mint_dpop_proof(agent=agent, htm="GET", htu=RESOURCE_URL, access_token=access_token)
    jwks = {"keys": [{**fake_rsa["jwk"], "kid": kid, "use": "sig", "alg": "RS256"}]}
    _expect_failure(
        verify_dpop_request(
            {
                "method": "GET",
                "url": RESOURCE_URL,
                "headers": {"authorization": f"DPoP {access_token}", "dpop": proof},
            },
            VerifyDPoPOptions(jwks=jwks, expected_issuer=EXPECTED_ISSUER),
        ),
        "bad_access_token_signature",
    )


def test_rejects_access_token_wrong_issuer():
    b = _build_request(access_token_kwargs={"iss": "https://attacker.example"})
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "bad_access_token_iss",
    )


def test_rejects_access_token_audience_mismatch():
    b = _build_request(access_token_kwargs={"aud": "unrelated-resource"})
    _expect_failure(
        verify_dpop_request(
            b["req"],
            VerifyDPoPOptions(
                jwks=b["jwks"],
                expected_issuer=EXPECTED_ISSUER,
                expected_audience=EXPECTED_AUDIENCE,
            ),
        ),
        "bad_access_token_aud",
    )


# ─── Federated audience: default expected_audience falls back to expected_issuer
# The Alien SSO mints `aud = [client_id, issuer]` so any agent-id token
# presented to any Alien-aware RS satisfies the default check.


def test_accepts_AT_with_issuer_in_aud_array_when_expected_audience_is_omitted():
    b = _build_request(access_token_kwargs={"aud": [EXPECTED_AUDIENCE, EXPECTED_ISSUER]})
    result = verify_dpop_request(
        b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)
    )
    assert result.ok, getattr(result, "error", None)


def test_accepts_AT_with_aud_eq_issuer_string_when_expected_audience_is_omitted():
    b = _build_request(access_token_kwargs={"aud": EXPECTED_ISSUER})
    result = verify_dpop_request(
        b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)
    )
    assert result.ok, getattr(result, "error", None)


def test_rejects_AT_whose_aud_lacks_the_issuer_when_expected_audience_is_omitted():
    # Defends against id_token confusion: an id+jwt from the same SSO
    # carries `aud = client_id` only (no issuer), and would have been
    # accepted under the pre-federation "skip aud" default.
    b = _build_request(access_token_kwargs={"aud": "some-client-id"})
    _expect_failure(
        verify_dpop_request(
            b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)
        ),
        "bad_access_token_aud",
    )


def test_accepts_AT_with_mismatching_aud_when_expected_audience_is_false():
    # Opt-out sentinel — discouraged outside test fixtures.
    b = _build_request(access_token_kwargs={"aud": "anything"})
    result = verify_dpop_request(
        b["req"],
        VerifyDPoPOptions(
            jwks=b["jwks"],
            expected_issuer=EXPECTED_ISSUER,
            expected_audience=False,
        ),
    )
    assert result.ok, getattr(result, "error", None)


def test_aud_string_match_uses_equality_not_substring():
    # RFC 7519 §4.1.3 audience check must be strict equality on the string
    # branch — a token aud of "test-resource-extra" must NOT match
    # expected_audience="test-resource".
    b = _build_request(access_token_kwargs={"aud": "test-resource-extra"})
    _expect_failure(
        verify_dpop_request(
            b["req"],
            VerifyDPoPOptions(
                jwks=b["jwks"],
                expected_issuer=EXPECTED_ISSUER,
                expected_audience="test-resource",
            ),
        ),
        "bad_access_token_aud",
    )


def test_aud_list_match_uses_membership():
    # When aud is a JSON array, expected_audience MUST be one of the entries
    # (RFC 7519 §4.1.3). Both presence and absence are checked.
    b = _build_request(access_token_kwargs={"aud": ["other-rs", "test-resource", "third"]})
    result = verify_dpop_request(
        b["req"],
        VerifyDPoPOptions(
            jwks=b["jwks"],
            expected_issuer=EXPECTED_ISSUER,
            expected_audience="test-resource",
        ),
    )
    assert result.ok, getattr(result, "error", None)

    b2 = _build_request(access_token_kwargs={"aud": ["a", "b", "c"]})
    _expect_failure(
        verify_dpop_request(
            b2["req"],
            VerifyDPoPOptions(
                jwks=b2["jwks"],
                expected_issuer=EXPECTED_ISSUER,
                expected_audience="test-resource",
            ),
        ),
        "bad_access_token_aud",
    )


def test_rejects_expired_access_token():
    past = int(time.time()) - 3600
    b = _build_request(access_token_kwargs={"iat": past - 60, "exp": past})
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "expired_access_token",
    )


# ─── RFC 9449 §6.1 + RFC 7800 §3.1: cnf.jkt binding ──────────────────────────


def test_rejects_access_token_without_cnf_jkt():
    b = _build_request(access_token_kwargs={"payload_overrides": {"cnf": None}})
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "missing_cnf_jkt",
    )


def test_rejects_access_token_jkt_mismatch():
    b = _build_request(access_token_kwargs={"agent_jkt": "A" * 43})
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "jkt_mismatch",
    )


# ─── RFC 9449 §4.3 step 10: ath binding ──────────────────────────────────────


def test_rejects_proof_iat_infinity():
    # RFC 8259 §6: JSON numbers do not include NaN/Infinity. Python's
    # default json.loads(allow_nan=True) accepts them as a non-standard
    # extension; the parser MUST reject so an attacker can't bypass
    # freshness via `now - NaN == NaN` not comparing to thresholds.
    b = _build_request()
    # Override the proof header completely with one that has iat=Infinity.
    agent = _generate_ed25519()
    rsa_pair = _generate_rsa()
    kid = "k1"
    agent_jkt = _jwk_thumbprint_okp(agent["jwk"])
    access_token = _mint_access_token(rsa_pair=rsa_pair, kid=kid, sub="s", agent_jkt=agent_jkt)
    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": agent["jwk"]}
    payload = {
        "jti": uuid.uuid4().hex,
        "htm": "GET",
        "htu": RESOURCE_URL,
        "iat": float("inf"),
        "ath": _sha256_b64url(access_token),
    }
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = agent["_priv"].sign(signing_input)
    proof = f"{h_b64}.{p_b64}.{_b64url(sig)}"
    jwks = {"keys": [{**rsa_pair["jwk"], "kid": kid, "use": "sig", "alg": "RS256"}]}
    _expect_failure(
        verify_dpop_request(
            {
                "method": "GET",
                "url": RESOURCE_URL,
                "headers": {"authorization": f"DPoP {access_token}", "dpop": proof},
            },
            VerifyDPoPOptions(jwks=jwks, expected_issuer=EXPECTED_ISSUER),
        ),
        "malformed_proof",
    )


def test_rejects_access_token_exp_infinity():
    agent = _generate_ed25519()
    rsa_pair = _generate_rsa()
    kid = "k1"
    agent_jkt = _jwk_thumbprint_okp(agent["jwk"])
    header = {"typ": "at+jwt", "alg": "RS256", "kid": kid}
    payload = {
        "iss": EXPECTED_ISSUER,
        "sub": "s",
        "aud": EXPECTED_AUDIENCE,
        "iat": int(time.time()),
        "exp": float("inf"),
        "cnf": {"jkt": agent_jkt},
    }
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = rsa_pair["_priv"].sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    access_token = f"{h_b64}.{p_b64}.{_b64url(sig)}"
    proof = _mint_dpop_proof(agent=agent, htm="GET", htu=RESOURCE_URL, access_token=access_token)
    jwks = {"keys": [{**rsa_pair["jwk"], "kid": kid, "use": "sig", "alg": "RS256"}]}
    _expect_failure(
        verify_dpop_request(
            {
                "method": "GET",
                "url": RESOURCE_URL,
                "headers": {"authorization": f"DPoP {access_token}", "dpop": proof},
            },
            VerifyDPoPOptions(jwks=jwks, expected_issuer=EXPECTED_ISSUER),
        ),
        "malformed_access_token",
    )


def test_rejects_proof_ath_mismatch():
    b = _build_request(
        proof_kwargs={"payload_overrides": {"ath": _sha256_b64url("different-token")}}
    )
    _expect_failure(
        verify_dpop_request(b["req"], VerifyDPoPOptions(jwks=b["jwks"], expected_issuer=EXPECTED_ISSUER)),
        "bad_proof_ath",
    )
