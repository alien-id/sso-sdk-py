"""RFC 9449 DPoP request verifier — Python port of
`packages/agent-id/src/index.ts` in the JS SDK.

Error codes are the same machine-readable labels as the JS package so
callers can compare across implementations.
"""

from __future__ import annotations

import hashlib
import math
import time
from collections import OrderedDict
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from alien_sso_agent_id._b64 import b64url_encode
from alien_sso_agent_id._crypto import jwk_thumbprint_okp, verify_eddsa_jwt, verify_rs256
from alien_sso_agent_id.jwks import DEFAULT_SSO_BASE_URL, EncryptedIdTokenError, parse_jwt
from alien_sso_agent_id.types import (
    JWK,
    VerifyDPoPFailure,
    VerifyDPoPOptions,
    VerifyDPoPResult,
    VerifyDPoPSuccess,
)


def _fail(code: str, error: str) -> VerifyDPoPFailure:
    return VerifyDPoPFailure(code=code, error=error)


# Module-scoped default jti replay cache. Single-process; production
# callers should pass a shared store via `opts.jti_store`.
_DEFAULT_JTI_CACHE_MAX = 10_000


class _DefaultJtiStore:
    def __init__(self) -> None:
        self._seen: OrderedDict[str, int] = OrderedDict()

    def has(self, jti: str) -> bool:
        return jti in self._seen

    def add(self, jti: str, iat: int) -> None:
        if len(self._seen) >= _DEFAULT_JTI_CACHE_MAX:
            self._seen.popitem(last=False)
        self._seen[jti] = iat


_default_jti_store = _DefaultJtiStore()


# WHATWG URL "special scheme" default ports — stripped during htu
# normalization so `https://example/path` and `https://example:443/path`
# compare equal, mirroring `new URL(...).toString()` in the JS SDK.
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


def _normalize_htu(s: str) -> str:
    parts = urlsplit(s)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"htu is not an absolute URL: {s!r}")
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    # Preserve userinfo (rare in htu but kept for WHATWG parity).
    userinfo = ""
    if parts.username:
        userinfo = parts.username
        if parts.password is not None:
            userinfo += ":" + parts.password
        userinfo += "@"
    port = parts.port
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    netloc = userinfo + (host if port is None else f"{host}:{port}")
    # WHATWG defaults the empty path to "/" for special schemes
    # (`new URL("https://h").toString()` → `"https://h/"`).
    path = parts.path
    if path == "" and scheme in _DEFAULT_PORTS:
        path = "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def _header_one(headers: Mapping[str, Any], name: str) -> tuple[Any, bool]:
    """Look up a header case-insensitively.

    Returns (value, is_duplicate). A duplicate is either a list-valued
    header or two distinct entries that differ only in case.
    """
    value: Any = None
    seen = 0
    for k, v in headers.items():
        if k.lower() == name.lower():
            value = v
            seen += 1
    if seen == 0:
        return None, False
    if seen > 1:
        return value, True
    if isinstance(value, list):
        return value, len(value) > 1
    return value, False


def verify_dpop_request(
    req: Mapping[str, Any],
    opts: VerifyDPoPOptions,
) -> VerifyDPoPResult:
    """Verify an inbound HTTP request carrying an RFC 9449 DPoP proof
    alongside an Alien at+jwt access token.

    Walks the RFC 9449 §4.3 checklist plus the §6.1 / RFC 7800 §3.1
    cnf.jkt binding and the RFC 9068 §4 access-token claim checks. On
    success, the caller can trust `sub` (the human owner per the SSO's
    signature) and `jkt` (the agent's DPoP key thumbprint per the
    proof's own signature).

    No custom envelope: every fact this function trusts is signed either
    by the SSO (over standard at+jwt claims) or by the agent (over the
    RFC 9449-defined DPoP proof claims).

    `req` is anything with `method`, `url`, and `headers` keys. A
    Starlette/FastAPI Request works too if accessed via its `method`,
    `url` (str-coerced) and `headers` properties.
    """
    method = req["method"]
    url = req["url"]
    headers = req["headers"]

    # §4.3 step 1: exactly one Authorization header carrying the DPoP scheme.
    auth_value, auth_dup = _header_one(headers, "authorization")
    if auth_dup or not isinstance(auth_value, str) or not auth_value:
        return _fail("missing_authorization", "Missing or duplicate Authorization header")
    # RFC 7235 §2.1: scheme names compare case-insensitively.
    parts = auth_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "dpop" or not parts[1].strip():
        return _fail("invalid_scheme", "Expected `Authorization: DPoP <access_token>`")
    access_token = parts[1].strip()
    if any(c.isspace() for c in access_token):
        return _fail("invalid_scheme", "Expected `Authorization: DPoP <access_token>`")

    # §4.3 step 1: exactly one DPoP proof header.
    dpop_value, dpop_dup = _header_one(headers, "dpop")
    if dpop_dup or not isinstance(dpop_value, str) or not dpop_value:
        return _fail("missing_dpop", "Missing or duplicate DPoP header")

    # §4.3 step 2: proof is a well-formed JWS.
    try:
        proof = parse_jwt(dpop_value)
    except EncryptedIdTokenError as err:
        return _fail("malformed_proof", f"Proof not a valid JWS: {err}")
    except (ValueError, TypeError) as err:
        return _fail("malformed_proof", f"Proof not a valid JWS: {err}")

    # §4.3 step 4: typ MUST be dpop+jwt.
    if proof.header.get("typ") != "dpop+jwt":
        return _fail(
            "bad_proof_typ",
            f"Proof typ must be 'dpop+jwt', got {proof.header.get('typ')!r}",
        )
    # §4.3 step 5: alg MUST be asymmetric, not none. Alien agents are
    # Ed25519, so EdDSA only.
    if proof.header.get("alg") != "EdDSA":
        return _fail(
            "bad_proof_alg",
            f"Proof alg must be 'EdDSA', got {proof.header.get('alg')!r}",
        )
    # §4.3 step 6: jwk in header, public only.
    proof_jwk = proof.header.get("jwk")
    if not isinstance(proof_jwk, dict):
        return _fail("missing_proof_jwk", "Proof header missing `jwk`")
    if (
        proof_jwk.get("kty") != "OKP"
        or proof_jwk.get("crv") != "Ed25519"
        or not isinstance(proof_jwk.get("x"), str)
    ):
        return _fail("bad_proof_jwk", "Proof jwk must be {kty:OKP, crv:Ed25519, x}")
    if "d" in proof_jwk:
        return _fail("private_in_proof_jwk", "Proof jwk leaks private member `d`")

    # §4.3 step 7: signature verifies with the embedded jwk.
    try:
        proof_sig_ok = verify_eddsa_jwt(
            proof.header_b64url,
            proof.payload_b64url,
            proof.signature_b64url,
            proof_jwk,
        )
    except Exception as err:  # noqa: BLE001 — surface as failure code
        return _fail("proof_sig_error", str(err))
    if not proof_sig_ok:
        return _fail("bad_proof_signature", "Proof signature failed verification")

    # §4.3 step 8: htm matches request method (case-sensitive per RFC 9449 §4.2).
    if proof.payload.get("htm") != method:
        return _fail(
            "bad_proof_htm",
            f"Proof htm {proof.payload.get('htm')!r} != request method {method!r}",
        )

    # §4.3 step 9: htu matches request URL, query+fragment stripped, with
    # symmetric URL normalization.
    try:
        request_htu = _normalize_htu(url)
        claimed_htu = _normalize_htu(str(proof.payload.get("htu")))
    except Exception:
        return _fail("bad_proof_htu", "Proof htu is not a parseable URL")
    if claimed_htu != request_htu:
        return _fail("bad_proof_htu", f"Proof htu {claimed_htu} != request URL {request_htu}")

    # §4.3 step 11: iat within ±max_age window.
    proof_max_age = opts.proof_max_age_sec
    iat_claim = proof.payload.get("iat")
    # RFC 7519 §4.1.6 NumericDate: a JSON number representing seconds since
    # the epoch. Python's json.loads accepts NaN/Infinity by default
    # (non-standard JSON); reject them so they can't bypass freshness.
    if (
        not isinstance(iat_claim, (int, float))
        or isinstance(iat_claim, bool)
        or not math.isfinite(iat_claim)
    ):
        return _fail("bad_proof_iat", "Proof iat is not a NumericDate")
    now_sec = int(time.time())
    age_sec = now_sec - int(iat_claim)
    if age_sec > proof_max_age:
        return _fail("stale_proof", f"Proof age {age_sec}s > max {proof_max_age}s")
    if age_sec < -proof_max_age:
        return _fail("future_proof", f"Proof iat {-age_sec}s in the future")

    # §4.3 step 12: jti not previously seen.
    jti_claim = proof.payload.get("jti")
    if not isinstance(jti_claim, str) or not jti_claim:
        return _fail("missing_proof_jti", "Proof missing jti")
    jti_store = opts.jti_store if opts.jti_store is not None else _default_jti_store
    if jti_store.has(jti_claim):
        return _fail("replayed_proof_jti", "Proof jti has already been seen")

    # §4.3 step 10 + RFC 9068 §4: parse + verify the access_token.
    try:
        at = parse_jwt(access_token)
    except EncryptedIdTokenError as err:
        return _fail("malformed_access_token", f"access_token not a JWS: {err}")
    except (ValueError, TypeError) as err:
        return _fail("malformed_access_token", f"access_token not a JWS: {err}")
    # RFC 9068 §2.1 + §4: typ MUST be at+jwt (or application/at+jwt).
    at_typ_raw = at.header.get("typ")
    at_typ_lc = at_typ_raw.lower() if isinstance(at_typ_raw, str) else ""
    if at_typ_lc not in ("at+jwt", "application/at+jwt"):
        return _fail(
            "bad_access_token_typ",
            f"access_token typ must be 'at+jwt' (RFC 9068 §4), got {at_typ_raw!r}",
        )

    # Resolve the signing key from the SSO JWKS.
    at_alg = at.header.get("alg")
    if at_alg != "RS256":
        return _fail("bad_access_token_alg", f"access_token alg must be RS256, got {at_alg!r}")
    kid = at.header.get("kid")
    jwk: JWK | None = None
    for k in opts.jwks.get("keys", []):
        if (
            k.get("kid") == kid
            and k.get("kty") == "RSA"
            and (k.get("use") == "sig" or k.get("use") is None)
            and (not k.get("alg") or k.get("alg") == "RS256")
        ):
            jwk = k
            break
    if jwk is None:
        return _fail("unknown_access_token_kid", f"No JWKS entry for kid={kid!r}")
    try:
        at_sig_ok = verify_rs256(at.header_b64url, at.payload_b64url, at.signature_b64url, jwk)
    except Exception as err:  # noqa: BLE001
        return _fail("access_token_sig_error", str(err))
    if not at_sig_ok:
        return _fail("bad_access_token_signature", "access_token signature failed verification")

    # RFC 9068 §4: claim checks.
    expected_issuer = opts.expected_issuer if opts.expected_issuer is not None else DEFAULT_SSO_BASE_URL
    if at.payload.get("iss") != expected_issuer:
        return _fail(
            "bad_access_token_iss",
            f"access_token iss {at.payload.get('iss')!r} != {expected_issuer}",
        )
    # RFC 9068 §4 audience check. Default: the AT `aud` must include
    # `expected_issuer` — the "federated audience" pattern. The Alien SSO
    # always emits `aud = [client_id, issuer]`, so any agent-id token
    # presented to any Alien-aware RS satisfies the default. Pass an
    # explicit string to scope to a specific client_id/resource, or
    # `False` to skip (test fixtures only).
    if opts.expected_audience is not False:
        expected_aud = (
            opts.expected_audience if opts.expected_audience is not None else expected_issuer
        )
        aud = at.payload.get("aud")
        # RFC 7519 §4.1.3: aud may be a string or array. Use strict
        # membership, not substring containment, on each branch.
        if isinstance(aud, list):
            aud_ok = expected_aud in aud
        else:
            aud_ok = aud == expected_aud
        if not aud_ok:
            return _fail(
                "bad_access_token_aud",
                f"access_token aud does not include {expected_aud}",
            )
    exp_claim = at.payload.get("exp")
    if (
        not isinstance(exp_claim, (int, float))
        or isinstance(exp_claim, bool)
        or not math.isfinite(exp_claim)
        or int(exp_claim) + opts.clock_skew_sec <= now_sec
    ):
        return _fail("expired_access_token", "access_token is expired")
    sub_claim = at.payload.get("sub")
    if not isinstance(sub_claim, str) or not sub_claim:
        return _fail("missing_access_token_sub", "access_token missing sub")

    # §6.1 + RFC 7800 §3.1: cnf.jkt MUST equal thumbprint(proof.jwk).
    cnf = at.payload.get("cnf")
    at_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if not isinstance(at_jkt, str) or not at_jkt:
        return _fail("missing_cnf_jkt", "access_token missing cnf.jkt")
    proof_jkt = jwk_thumbprint_okp(proof_jwk)
    if at_jkt != proof_jkt:
        return _fail(
            "jkt_mismatch",
            f"access_token cnf.jkt {at_jkt} != proof jwk thumbprint {proof_jkt}",
        )

    # §4.3 step 10: ath = b64url(sha256(access_token)).
    expected_ath = b64url_encode(hashlib.sha256(access_token.encode("utf-8")).digest())
    if proof.payload.get("ath") != expected_ath:
        return _fail("bad_proof_ath", "Proof ath does not match sha256(access_token)")

    # All checks passed — record jti and return.
    jti_store.add(jti_claim, int(iat_claim))

    return VerifyDPoPSuccess(
        sub=sub_claim,
        jkt=proof_jkt,
        access_token_claims=dict(at.payload),
        proof_claims=dict(proof.payload),
    )
