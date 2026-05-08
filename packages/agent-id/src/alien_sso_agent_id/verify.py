"""Token verification — Python port of `@alien-id/sso-agent-id`.

Error strings match the JS package verbatim so callers can do equality
checks across implementations.
"""

from __future__ import annotations

import json
import math
import time
from typing import Any, Mapping, Union

from alien_sso_agent_id._b64 import b64url_decode
from alien_sso_agent_id._canonical import canonical_json_string
from alien_sso_agent_id._crypto import (
    ed25519_jwk_thumbprint,
    fingerprint_public_key_pem,
    sha256_hex,
    verify_ed25519_b64url,
    verify_ed25519_hex,
    verify_rs256,
)
from alien_sso_agent_id.jwks import EncryptedIdTokenError, parse_jwt
from alien_sso_agent_id.types import (
    VerifyFailure,
    VerifyOwnerOptions,
    VerifyOwnerSuccess,
    VerifyOptions,
    VerifyResult,
    VerifySuccess,
)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _fail(error: str) -> VerifyFailure:
    return VerifyFailure(error=error)


_OMITTED = object()


def verify_agent_token(
    token_b64: str,
    opts: VerifyOptions | None = None,
) -> VerifyResult:
    """Verify an Alien Agent ID token.

    Confirms the agent holds the private key, the fingerprint matches the
    public key, and the token is fresh. Does NOT verify owner — see
    `verify_agent_token_with_owner` for that.
    """
    o = opts or VerifyOptions()

    try:
        raw = b64url_decode(token_b64).decode("utf-8")
        parsed = json.loads(raw)
    except Exception:
        return _fail("Invalid token encoding")

    if not isinstance(parsed, dict):
        return _fail("Invalid token encoding")

    if parsed.get("v") != 1:
        return _fail(f"Unsupported token version: {parsed.get('v')}")

    sig = parsed.get("sig")
    fingerprint = parsed.get("fingerprint")
    public_key_pem = parsed.get("publicKeyPem")
    timestamp = parsed.get("timestamp")
    nonce = parsed.get("nonce")
    owner = parsed.get("owner", _OMITTED)

    if not isinstance(sig, str):
        return _fail("Missing or invalid field: sig")
    if not isinstance(fingerprint, str):
        return _fail("Missing or invalid field: fingerprint")
    if not isinstance(public_key_pem, str):
        return _fail("Missing or invalid field: publicKeyPem")
    # JS check: typeof === 'number' && Number.isFinite. JSON.stringify(Infinity) → null,
    # which is not a number — so non-finite floats and missing both fail this check.
    if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool) or not math.isfinite(timestamp):
        return _fail("Missing or invalid field: timestamp")
    if not isinstance(nonce, str):
        return _fail("Missing or invalid field: nonce")
    if owner is not _OMITTED and owner is not None and not isinstance(owner, str):
        return _fail("Invalid field: owner")

    age = _now_ms() - int(timestamp)
    if age < -o.clock_skew_ms or age > o.max_age_ms:
        return _fail(f"Token expired (age: {round(age / 1000)}s)")

    try:
        computed_fp = fingerprint_public_key_pem(public_key_pem)
    except Exception:
        return _fail("Invalid public key in token")
    if computed_fp != fingerprint:
        return _fail("Fingerprint does not match public key")

    payload_fields: dict[str, Any] = {
        "v": parsed["v"],
        "fingerprint": fingerprint,
        "publicKeyPem": public_key_pem,
        "timestamp": timestamp,
        "nonce": nonce,
    }
    if owner is not _OMITTED:
        payload_fields["owner"] = owner

    canonical = canonical_json_string(payload_fields)
    try:
        sig_ok = verify_ed25519_b64url(canonical, sig, public_key_pem)
    except Exception:
        return _fail("Signature verification error")
    if not sig_ok:
        return _fail("Signature verification failed")

    return VerifySuccess(
        fingerprint=fingerprint,
        public_key_pem=public_key_pem,
        owner=owner if owner is not _OMITTED else None,
        owner_verified=False,
        timestamp=int(timestamp),
        nonce=nonce,
    )


def verify_agent_token_with_owner(
    token_b64: str,
    opts: VerifyOwnerOptions,
) -> VerifyResult:
    """Verify a token AND its owner chain against the provided JWKS.

    Steps mirror the JS `verifyAgentTokenWithOwner`:
      1. Basic token verification (`verify_agent_token`).
      2. ownerBinding payload hash matches.
      3. ownerBinding signed by the agent's key.
      4. Binding agentInstance fingerprint matches.
      5. Binding ownerSessionSub matches the token's owner claim.
      6. id_token hash matches binding.
      7. id_token RS256 signature verifies against the JWKS.
      8. id_token sub matches the token owner.
      9. (optional) ownerSessionProof signature verifies.
    """
    basic = verify_agent_token(
        token_b64,
        VerifyOptions(max_age_ms=opts.max_age_ms, clock_skew_ms=opts.clock_skew_ms),
    )
    if not basic.ok or isinstance(basic, VerifyFailure):
        return basic

    assert isinstance(basic, VerifySuccess)

    parsed = json.loads(b64url_decode(token_b64).decode("utf-8"))

    owner_binding = parsed.get("ownerBinding")
    id_token = parsed.get("idToken")

    if not isinstance(owner_binding, dict):
        return _fail("Missing field: ownerBinding")
    if not isinstance(id_token, str):
        return _fail("Missing field: idToken")
    if not basic.owner:
        return _fail("Token has no owner to verify")

    payload = owner_binding.get("payload")
    payload_hash = owner_binding.get("payloadHash")
    signature = owner_binding.get("signature")

    if not isinstance(payload, dict):
        return _fail("Invalid ownerBinding.payload")
    if not isinstance(payload_hash, str):
        return _fail("Invalid ownerBinding.payloadHash")
    if not isinstance(signature, str):
        return _fail("Invalid ownerBinding.signature")

    binding_canonical = canonical_json_string(payload)
    if sha256_hex(binding_canonical) != payload_hash:
        return _fail("Owner binding payload hash mismatch")

    try:
        binding_ok = verify_ed25519_b64url(binding_canonical, signature, basic.public_key_pem)
    except Exception:
        return _fail("Owner binding signature verification error")
    if not binding_ok:
        return _fail("Owner binding signature verification failed")

    agent_instance = payload.get("agentInstance")
    if (
        not isinstance(agent_instance, dict)
        or agent_instance.get("publicKeyFingerprint") != basic.fingerprint
    ):
        return _fail("Owner binding agent fingerprint mismatch")

    if payload.get("ownerSessionSub") != basic.owner:
        return _fail("Owner binding ownerSessionSub mismatch")

    if payload.get("idTokenHash") != sha256_hex(id_token):
        return _fail("id_token hash does not match owner binding")

    try:
        jwt = parse_jwt(id_token)
    except EncryptedIdTokenError:
        # OIDC §3.1.3.7 / RFC 7516: encrypted ID tokens are not supported;
        # surface the policy explicitly rather than as a parse failure.
        return _fail("Encrypted ID Tokens (JWE) are not supported")
    except (ValueError, TypeError):
        # parse_jwt raises ValueError on shape errors (split count, non-JSON,
        # non-object header/payload) and TypeError on input-type confusion.
        # binascii.Error is a ValueError subclass, covered here too.
        return _fail("Invalid id_token encoding")

    if jwt.header.get("alg") != "RS256":
        return _fail(f"Unsupported id_token alg: {jwt.header.get('alg')}")

    # RFC 8725 §3.7 / RFC 7515 §4.1.9: when typ is present it MUST identify
    # this as an id_token. Reject any cross-class typ (e.g. at+jwt) so a
    # smuggled access token cannot be accepted as an id_token.
    typ = jwt.header.get("typ")
    if typ is not None:
        if not isinstance(typ, str):
            return _fail("id_token typ must be a string")
        typ_lc = typ.lower()
        if typ_lc not in ("jwt", "application/jwt"):
            return _fail(f"id_token typ {typ!r} is not jwt/application/jwt")

    # RFC 7515 §4.1.11: any unrecognised critical header MUST cause
    # rejection. We support no JWS extensions; reject any non-empty crit.
    crit = jwt.header.get("crit")
    if crit is not None and (not isinstance(crit, list) or len(crit) > 0):
        return _fail("id_token contains unsupported crit header")

    kid = jwt.header.get("kid")
    matching: dict[str, Any] | None = None
    for k in opts.jwks.get("keys", []):
        if k.get("kid") == kid and k.get("kty") == "RSA" and (k.get("use") == "sig" or k.get("use") is None):
            matching = k
            break
    if matching is None:
        return _fail(f"No matching JWKS key for kid: {kid}")
    # RFC 7515 §10.7: when the JWK pins an `alg`, it MUST match the JWS
    # alg. Permissive when the JWK omits alg (RFC 7517 §4.4: optional).
    jwk_alg = matching.get("alg")
    if jwk_alg is not None and jwk_alg != "RS256":
        return _fail(f"Invalid JWKS key: alg {jwk_alg} does not match RS256")
    if not matching.get("n") or not matching.get("e"):
        return _fail("Invalid JWKS key: missing required RSA fields (n, e)")

    try:
        rsa_ok = verify_rs256(jwt.header_b64url, jwt.payload_b64url, jwt.signature_b64url, matching)
    except Exception:
        return _fail("id_token signature verification error")
    if not rsa_ok:
        return _fail("id_token signature verification failed")

    # RFC 7519 §4.1.4 / §7.2: exp MUST be in the future. OIDC Core §2
    # makes it REQUIRED on id_token — a missing exp is a hard fail.
    now_sec = int(time.time())
    skew_sec = opts.clock_skew_ms // 1000
    exp = jwt.payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return _fail("id_token missing exp")
    if now_sec >= int(exp) + skew_sec:
        return _fail("id_token expired")
    # RFC 7519 §4.1.5: when nbf is present, current time MUST be ≥ nbf.
    nbf = jwt.payload.get("nbf")
    if isinstance(nbf, (int, float)) and not isinstance(nbf, bool):
        if now_sec < int(nbf) - skew_sec:
            return _fail("id_token not yet valid")

    # RFC 7519 §4.1.6: "iat" value MUST be a number containing a NumericDate
    # value. Optional, but when present must be a numeric type (excluding bool).
    if "iat" in jwt.payload:
        iat = jwt.payload.get("iat")
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            return _fail("id_token iat must be a NumericDate")

    if jwt.payload.get("sub") != basic.owner:
        return _fail("id_token sub does not match token owner")

    # RFC 7519 §4.1.1 / RFC 9068 §5: iss MUST exactly match.
    if jwt.payload.get("iss") != opts.expected_issuer:
        return _fail("id_token iss does not match expected issuer")

    # RFC 7519 §4.1.3: aud may be a string or array; the principal MUST
    # be identified by at least one value when it is present.
    aud_claim = jwt.payload.get("aud")
    token_auds = aud_claim if isinstance(aud_claim, list) else [aud_claim]
    expected = (
        opts.expected_audience
        if isinstance(opts.expected_audience, list)
        else [opts.expected_audience]
    )
    if not any(a in token_auds for a in expected):
        return _fail("id_token aud does not match expected audience")
    # OIDC §3.1.3.7 step 3: "MUST be rejected ... if it contains additional
    # audiences not trusted by the Client." Default trust = expected set.
    trusted = opts.trusted_audiences if opts.trusted_audiences is not None else set(expected)
    for a in token_auds:
        if a not in trusted:
            return _fail("id_token contains untrusted audience")

    # OIDC Core §3.1.3.7.6 / .7: if `azp` is present, it MUST match the
    # client_id (i.e., expected_audience). Multi-aud without `azp` is a
    # SHOULD-level recommendation we do not enforce (the AS issued the
    # token; we still trust the iss/aud match above).
    azp = jwt.payload.get("azp")
    if azp is not None:
        if not isinstance(azp, str) or not any(a == azp for a in expected):
            return _fail("id_token azp does not match expected audience")

    # cnf.jkt MUST equal RFC 7638 thumbprint of the agent's public key
    # (RFC 7800 §3.1 / RFC 9449 §6.1). Without this check the id_token
    # is not bound to the presenting agent — an attacker can substitute
    # their own keypair across the binding payload + proof bundle while
    # reusing a stolen id_token verbatim. Anchors at the agent key, not
    # the binding's self-embedded key.
    try:
        expected_jkt = ed25519_jwk_thumbprint(basic.public_key_pem)
    except (ValueError, TypeError) as err:
        return _fail(f"cnf.jkt anchor: {err}")
    cnf = jwt.payload.get("cnf")
    actual_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if not isinstance(actual_jkt, str) or not actual_jkt:
        return _fail("id_token missing cnf.jkt")
    if actual_jkt != expected_jkt:
        return _fail("id_token cnf.jkt does not bind to agent key")

    owner_proof_verified = False
    proof = payload.get("ownerSessionProof")
    if isinstance(proof, dict):
        session_address = proof.get("sessionAddress")
        session_signature = proof.get("sessionSignature")
        session_seed = proof.get("sessionSignatureSeed")
        session_pubkey = proof.get("sessionPublicKey")

        if (
            not isinstance(session_address, str)
            or not isinstance(session_signature, str)
            or not isinstance(session_seed, str)
            or not isinstance(session_pubkey, str)
        ):
            return _fail("Incomplete owner session proof fields")

        if session_address != basic.owner:
            return _fail("Owner session proof address mismatch")

        message = f"{session_address}{session_seed}"
        try:
            proof_ok = verify_ed25519_hex(message, session_signature, session_pubkey)
        except Exception:
            return _fail("Owner session proof signature error")
        if not proof_ok:
            return _fail("Owner session proof signature failed")
        owner_proof_verified = True

    issuer = jwt.payload.get("iss")
    return VerifyOwnerSuccess(
        fingerprint=basic.fingerprint,
        public_key_pem=basic.public_key_pem,
        owner=basic.owner,
        timestamp=basic.timestamp,
        nonce=basic.nonce,
        issuer=issuer if isinstance(issuer, str) else "",
        owner_proof_verified=owner_proof_verified,
    )


# ─── Request helpers ──────────────────────────────────────────────────────

_HeadersLike = Union[Mapping[str, Any], Any]


def _extract_token(headers: _HeadersLike) -> tuple[str | None, VerifyFailure | None]:
    """Pull the AgentID token from a request-like object's headers.

    Accepts:
    - Mapping[str, str] (case-insensitive lookup attempted)
    - Anything with a `.get()` (Starlette Headers, http.Headers, etc.)
    - Anything with a `.headers` attribute that is itself headers-like
    """
    auth = _header_value(headers, "authorization")
    if isinstance(auth, list):
        return None, _fail("Multiple Authorization headers")
    if not isinstance(auth, str) or not auth.startswith("AgentID "):
        return None, _fail("Missing header: Authorization: AgentID <token>")
    return auth[len("AgentID "):].strip(), None


def _header_value(source: Any, name: str) -> Any:
    headers = getattr(source, "headers", None)
    if headers is None and isinstance(source, Mapping) and "headers" in source:
        headers = source["headers"]
    if headers is None:
        headers = source
    if hasattr(headers, "getlist"):
        try:
            values = headers.getlist(name)
            if len(values) > 1:
                return values
            if len(values) == 1:
                return values[0]
        except Exception:
            pass
    if hasattr(headers, "get"):
        v = headers.get(name)
        if v is None:
            v = headers.get(name.lower())
        if v is None:
            v = headers.get(name.title())
        return v
    if isinstance(headers, Mapping):
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
    return None


def verify_agent_request(req: _HeadersLike, opts: VerifyOptions | None = None) -> VerifyResult:
    """Extract and verify an Agent ID token from an HTTP request.

    Works with anything exposing a `headers` mapping — Starlette `Request`,
    Flask `request`, raw dicts, etc.
    """
    token, err = _extract_token(req)
    if err is not None:
        return err
    assert token is not None
    return verify_agent_token(token, opts)


def verify_agent_request_with_owner(req: _HeadersLike, opts: VerifyOwnerOptions) -> VerifyResult:
    token, err = _extract_token(req)
    if err is not None:
        return err
    assert token is not None
    return verify_agent_token_with_owner(token, opts)
