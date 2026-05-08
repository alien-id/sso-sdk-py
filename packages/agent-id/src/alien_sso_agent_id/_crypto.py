"""Low-level Ed25519 / RS256 / fingerprinting helpers.

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


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def fingerprint_public_key_pem(pem: str) -> str:
    """SHA-256 of the SPKI DER encoding of the Ed25519 public key, hex."""
    pub = serialization.load_pem_public_key(pem.encode("ascii"))
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def verify_ed25519_b64url(payload: bytes | str, signature_b64url: str, public_key_pem: str) -> bool:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    pub = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    try:
        pub.verify(b64url_decode(signature_b64url), payload)
    except InvalidSignature:
        return False
    return True


_ED25519_RAW_KEY_LENGTH = 32
# SPKI prefix for an Ed25519 raw public key: SEQUENCE(SEQUENCE(OID 1.3.101.112), BIT STRING(32 bytes))
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def ed25519_jwk_thumbprint(public_key_pem: str) -> str:
    """RFC 7638 JWK Thumbprint of an Ed25519 public key (PEM SPKI).

    Canonical JSON for an OKP/Ed25519 key is exactly
    ``{"crv":"Ed25519","kty":"OKP","x":"<x>"}`` — lex-ordered members,
    no whitespace. SHA-256 the bytes, then base64url (no padding).

    Used to verify ``cnf.jkt`` on an SSO-issued id_token: the thumbprint
    of the agent's public key MUST equal the id_token's ``cnf.jkt`` for
    proof-of-possession (RFC 7800 §3.1, RFC 9449 §6.1).
    """
    pub = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("ed25519_jwk_thumbprint: not an Ed25519 public key")
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if len(der) != 44 or not der.startswith(_ED25519_SPKI_PREFIX):
        raise ValueError("ed25519_jwk_thumbprint: not an Ed25519 SPKI public key")
    raw = der[12:]
    x = b64url_encode(raw)
    canonical = f'{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}'.encode("ascii")
    return b64url_encode(hashlib.sha256(canonical).digest())


def verify_ed25519_hex(message: str, signature_hex: str, public_key_hex: str) -> bool:
    raw = bytes.fromhex(public_key_hex)
    if len(raw) != _ED25519_RAW_KEY_LENGTH:
        raise ValueError(
            f"Invalid Ed25519 public key: expected {_ED25519_RAW_KEY_LENGTH} bytes, got {len(raw)}"
        )
    pub = serialization.load_der_public_key(_ED25519_SPKI_PREFIX + raw)
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("derived key is not Ed25519")
    try:
        pub.verify(bytes.fromhex(signature_hex), message.encode("utf-8"))
    except InvalidSignature:
        return False
    return True


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
