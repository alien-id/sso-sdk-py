"""Local id_token verifier — minimal JWS RS256 + claims validation.

Imported by `client.AlienSsoClient.get_auth_data()` so callers receive only
claims from a fully-validated id_token (OIDC §3.1.3.7). We deliberately
keep this tiny — full JOSE handling lives in `alien-sso-agent-id`. Here we
only support RS256 because that is what the SSO backend mints for OIDC.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


_HTTP_TIMEOUT = 5.0
_JWKS_TTL_SECONDS = 24 * 60 * 60  # OIDC discovery: refresh daily.


# RFC 7515 §2 / RFC 7519 §7.2: base64url segments use the RFC 4648 §5
# alphabet WITHOUT padding "or other additional characters." Python's
# urlsafe_b64decode silently tolerates whitespace and a 5-char-residue
# input — we pre-screen the segment before decoding.
_B64URL_ALPHABET_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64url_decode(s: str) -> bytes:
    if not _B64URL_ALPHABET_RE.fullmatch(s):
        raise ValueError("Invalid base64url segment (RFC 7515 §2)")
    if len(s) % 4 == 1:
        raise ValueError("Invalid base64url length (RFC 7515 §2)")
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@dataclass(frozen=True)
class _ParsedJwt:
    header_b64: str
    payload_b64: str
    signature_b64: str
    header: dict[str, Any]
    payload: dict[str, Any]


class EncryptedIdTokenError(ValueError):
    """Raised when an id_token is a JWE (RFC 7516) instead of a JWS.

    OIDC §3.1.3.7 requires the client to decrypt or reject. We do not
    implement decryption, so this surfaces the policy explicitly.
    """


def parse_jwt(token: str) -> _ParsedJwt:
    parts = token.split(".")
    # RFC 7516 §9: JWEs have five segments separated by four periods.
    if len(parts) == 5:
        raise EncryptedIdTokenError(
            "Encrypted ID Tokens (JWE) are not supported"
        )
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected 3 parts")
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("Invalid JWT: header/payload must be JSON objects")
    # RFC 7516 §4.1.2: `enc` is JWE-only; a 3-part token carrying it is
    # mis-routed encryption — reject under the same policy.
    if "enc" in header:
        raise EncryptedIdTokenError(
            "Encrypted ID Tokens (JWE) are not supported"
        )
    return _ParsedJwt(parts[0], parts[1], parts[2], header, payload)


# RFC 7518 §3.3 / RFC 8725 §3.5: RS256 keys MUST be ≥ 2048 bits. The JWK
# `n` parameter is the unsigned modulus encoded base64url with no leading
# zero byte (RFC 7518 §6.3.1), so 256 bytes corresponds to exactly 2048 bits.
_MIN_RSA_MODULUS_BYTES = 256


def _verify_rs256(jwt: _ParsedJwt, jwk: dict[str, Any]) -> bool:
    n_b = _b64url_decode(jwk["n"])
    if len(n_b) < _MIN_RSA_MODULUS_BYTES:
        return False
    e_b = _b64url_decode(jwk["e"])
    n = int.from_bytes(n_b, "big")
    e = int.from_bytes(e_b, "big")
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    signing_input = f"{jwt.header_b64}.{jwt.payload_b64}".encode("ascii")
    sig = _b64url_decode(jwt.signature_b64)
    try:
        pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def _select_jwk(jwks: dict[str, Any], kid: Optional[str], alg: str) -> Optional[dict[str, Any]]:
    for k in jwks.get("keys", []):
        if not isinstance(k, dict):
            continue
        if k.get("kty") != "RSA":
            continue
        if kid is not None and k.get("kid") != kid:
            continue
        # RFC 7517 §4.2 / §8.2.2: when `use` is present it constrains the
        # key's intended purpose. A JWS verifier MUST skip encryption-only
        # keys ("enc") to defend against JWK confusion across the JWKS.
        # Absent `use` is permitted (unspecified).
        jwk_use = k.get("use")
        if jwk_use is not None and jwk_use != "sig":
            continue
        # RFC 7515 §10.7: when JWK pins alg, it MUST match.
        jwk_alg = k.get("alg")
        if jwk_alg is not None and jwk_alg != alg:
            continue
        if not k.get("n") or not k.get("e"):
            continue
        return k
    return None


def fetch_jwks_sync(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"JWKS fetch failed: {resp.status}")
        body = resp.read()
    parsed = json.loads(body)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), list):
        raise ValueError("JWKS response missing keys[]")
    return parsed


@dataclass
class JwksCache:
    """Single-slot in-memory JWKS cache keyed by URL."""

    url: str
    _jwks: Optional[dict[str, Any]] = None
    _fetched_at: float = 0.0

    def get(self, *, force_refresh: bool = False) -> dict[str, Any]:
        if (
            force_refresh
            or self._jwks is None
            or (time.time() - self._fetched_at) > _JWKS_TTL_SECONDS
        ):
            self._jwks = fetch_jwks_sync(self.url)
            self._fetched_at = time.time()
        return self._jwks

    def inject(self, jwks: dict[str, Any]) -> None:
        """Test/dev seam — inject a JWKS without HTTP."""
        self._jwks = jwks
        self._fetched_at = time.time()


@dataclass(frozen=True)
class VerifiedIdToken:
    payload: dict[str, Any]


def verify_id_token(
    token: str,
    *,
    jwks: dict[str, Any],
    expected_issuer: str,
    expected_audience: str,
    expected_nonce: Optional[str],
    clock_skew_sec: int = 30,
    trusted_audiences: Optional[set[str]] = None,
) -> Optional[VerifiedIdToken]:
    """Full OIDC §3.1.3.7 id_token validation. Returns None on any failure."""
    try:
        jwt = parse_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return None

    # RFC 9068 §5 / RFC 7515 §4.1.9 + RFC 6838 §4.2: typ comparison is
    # case-insensitive; bare value gets `application/` prepended. We
    # accept the OIDC `JWT` family and reject AT-shaped types.
    typ_raw = jwt.header.get("typ")
    typ_lower = typ_raw.lower() if isinstance(typ_raw, str) else "jwt"
    if typ_lower not in ("jwt", "application/jwt"):
        return None

    if jwt.header.get("alg") != "RS256":
        return None

    # RFC 7515 §4.1.11: any unrecognised critical header MUST cause rejection.
    crit = jwt.header.get("crit")
    if crit is not None and (not isinstance(crit, list) or len(crit) > 0):
        return None

    jwk = _select_jwk(jwks, jwt.header.get("kid"), "RS256")
    if jwk is None:
        return None
    try:
        if not _verify_rs256(jwt, jwk):
            return None
    except Exception:
        return None

    payload = jwt.payload
    if payload.get("iss") != expected_issuer:
        return None

    aud_claim = payload.get("aud")
    aud_list = aud_claim if isinstance(aud_claim, list) else [aud_claim]
    if expected_audience not in aud_list:
        return None
    # OIDC §3.1.3.7 step 3: "The ID Token MUST be rejected ... if it
    # contains additional audiences not trusted by the Client." Caller can
    # widen the trusted set; default rejects anything beyond expected_audience.
    trusted = trusted_audiences if trusted_audiences is not None else {expected_audience}
    for a in aud_list:
        if a not in trusted:
            return None

    # OIDC §3.1.3.7 step 4: "If the ID Token contains multiple audiences,
    # the Client SHOULD verify that an azp Claim is present." We treat
    # this as MUST: a multi-audience ID Token without azp is structurally
    # ambiguous about its authorized party and is rejected.
    azp = payload.get("azp")
    if isinstance(aud_claim, list) and len(aud_list) > 1 and azp is None:
        return None
    # OIDC §3.1.3.7.6 / .7: when azp is present, MUST equal client_id.
    if azp is not None and azp != expected_audience:
        return None

    now = int(time.time())
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return None
    if now >= int(exp) + clock_skew_sec:
        return None

    # RFC 7519 §4.1.5 / RFC 8725: nbf, when present, MUST be a NumericDate.
    # Silently ignoring a non-numeric nbf would let an attacker bypass the
    # not-before check by sending a string. Reject malformed values up-front.
    nbf = payload.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, (int, float)) or isinstance(nbf, bool):
            return None
        if now < int(nbf) - clock_skew_sec:
            return None

    # RFC 7519 §4.1.6: iat, when present, MUST be a NumericDate. Reject
    # non-numeric values up-front so the schema layer doesn't carry a
    # malformed claim past this verifier (defense-in-depth — the schema
    # also rejects, but the type-check belongs at the verifier boundary).
    iat = payload.get("iat")
    if iat is not None:
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            return None

    if expected_nonce is not None and payload.get("nonce") != expected_nonce:
        return None

    return VerifiedIdToken(payload=payload)
