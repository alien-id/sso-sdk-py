"""Low-level RS256 + Ed25519 (EdDSA-JWS) helpers.

Mirrors `packages/agent-id/src/crypto.ts` from the JS SDK.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from alien_sso_agent_id._b64 import b64url_decode, b64url_encode
from alien_sso_agent_id.types import JWK

# RFC 7518 §3.3 / RFC 8725 §3.5: RS256 keys MUST be ≥ 2048 bits. The JWK
# `n` parameter is the unsigned modulus encoded base64url with no leading
# zero byte (RFC 7518 §6.3.1), so 256 bytes corresponds to exactly 2048 bits.
_MIN_RSA_MODULUS_BYTES = 256


def verify_rs256(header_b64url: str, payload_b64url: str, signature_b64url: str, jwk: JWK) -> bool:
    n_b = b64url_decode(jwk["n"])  # type: ignore[index]
    if len(n_b) < _MIN_RSA_MODULUS_BYTES:
        return False
    n = int.from_bytes(n_b, "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")  # type: ignore[index]
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    signing_input = f"{header_b64url}.{payload_b64url}".encode("ascii")
    try:
        pub.verify(
            b64url_decode(signature_b64url),
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def jwk_thumbprint_okp(jwk: dict) -> str:
    """RFC 7638 JWK Thumbprint of an OKP/Ed25519 JWK.

    Canonical members are `{"crv","kty","x"}` in lexical order with no
    whitespace. SHA-256, then base64url (no padding). Raises ValueError if
    the JWK is not a well-formed OKP/Ed25519 public key.
    """
    if jwk.get("kty") != "OKP":
        raise ValueError(f"jwk_thumbprint_okp: kty must be OKP, got {jwk.get('kty')!r}")
    if jwk.get("crv") != "Ed25519":
        raise ValueError(f"jwk_thumbprint_okp: crv must be Ed25519, got {jwk.get('crv')!r}")
    x = jwk.get("x")
    if not isinstance(x, str) or not x:
        raise ValueError("jwk_thumbprint_okp: x is required")
    canonical = f'{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}'.encode("ascii")
    return b64url_encode(hashlib.sha256(canonical).digest())


# RFC 8037 §2: Ed25519 SPKI is a fixed 12-byte AlgorithmIdentifier prefix
# + 32 raw key bytes.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ED25519_RAW_KEY_LENGTH = 32


def verify_eddsa_jwt(
    header_b64url: str,
    payload_b64url: str,
    signature_b64url: str,
    jwk: dict,
) -> bool:
    """Verify an EdDSA (Ed25519) JWS detached signature against an OKP JWK.

    Used to check DPoP proofs (RFC 9449 §4.3 step 7) — the public key is
    carried in the proof's own `jwk` header.
    """
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return False
    x = jwk.get("x")
    if not isinstance(x, str):
        return False
    raw = b64url_decode(x)
    if len(raw) != _ED25519_RAW_KEY_LENGTH:
        return False
    der = _ED25519_SPKI_PREFIX + raw
    pub = serialization.load_der_public_key(der)
    if not isinstance(pub, Ed25519PublicKey):
        return False
    signing_input = f"{header_b64url}.{payload_b64url}".encode("ascii")
    try:
        pub.verify(b64url_decode(signature_b64url), signing_input)
    except InvalidSignature:
        return False
    return True
