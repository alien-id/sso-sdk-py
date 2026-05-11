"""Shared test helpers — mirror the JS test fixtures in
`packages/agent-id/tests/verify.test.ts` + `verify-owner.test.ts`."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@dataclass
class Ed25519Pair:
    public_key_pem: str
    private_key_pem: str
    public_key_hex: str
    private_key_raw: str
    _private: Ed25519PrivateKey
    _public: Ed25519PublicKey


def generate_ed25519() -> Ed25519Pair:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pem_pub = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    pem_priv = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    der_pub = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_hex = der_pub[12:].hex()  # strip SPKI prefix → 32 bytes
    der_priv = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    private_hex = der_priv[16:].hex()  # strip PKCS8 prefix → 32 bytes
    return Ed25519Pair(pem_pub, pem_priv, public_hex, private_hex, priv, pub)


@dataclass
class RsaPair:
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey
    jwk: dict[str, str]


def generate_rsa() -> RsaPair:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    n = pub.public_numbers().n
    e = pub.public_numbers().e
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    jwk = {
        "kty": "RSA",
        "n": b64url(n_bytes),
        "e": b64url(e_bytes),
    }
    return RsaPair(pub, priv, jwk)


def fingerprint_pem(pem: str) -> str:
    pub = serialization.load_pem_public_key(pem.encode("ascii"))
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def ed25519_thumbprint(pem: str) -> str:
    """RFC 7638 thumbprint for an Ed25519 public key (PEM-encoded SPKI).

    Mirrors ``ed25519_jwk_thumbprint`` in
    ``src/alien_sso_agent_id/_crypto.py`` so the test fixture stays
    decoupled from the production helper while producing the
    byte-identical ``jkt`` the verifier checks against ``cnf.jkt``.
    """
    pub = serialization.load_pem_public_key(pem.encode("ascii"))
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # SPKI for Ed25519 is 12 bytes of fixed prefix + 32 raw key bytes.
    x = b64url(der[12:])
    canonical = f'{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}'.encode("ascii")
    return b64url(hashlib.sha256(canonical).digest())


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _sort_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_sort_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _sort_value(value[k]) for k in sorted(value.keys())}
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_sort_value(value), separators=(",", ":"), ensure_ascii=False)


def sign_ed25519_b64url(data: str, priv_pem: str) -> str:
    priv = serialization.load_pem_private_key(priv_pem.encode("ascii"), password=None)
    return b64url(priv.sign(data.encode("utf-8")))


def sign_ed25519_hex(message: str, priv_pem: str) -> str:
    priv = serialization.load_pem_private_key(priv_pem.encode("ascii"), password=None)
    return priv.sign(message.encode("utf-8")).hex()


def sign_rs256(data: bytes, priv: rsa.RSAPrivateKey) -> bytes:
    return priv.sign(data, padding.PKCS1v15(), hashes.SHA256())


def now_ms() -> int:
    return int(time.time() * 1000)


def random_hex(n: int) -> str:
    return os.urandom(n).hex()


def build_token(
    pair: Ed25519Pair | None = None,
    *,
    fingerprint: str | None = None,
    timestamp: int | None = None,
    nonce: str | None = None,
    owner: str | None = ...,  # type: ignore[assignment]
    v: Any = 1,
    extra_fields: dict[str, Any] | None = None,
    skip_sign: bool = False,
    override_sig: str | None = None,
) -> str:
    """Equivalent of the JS `buildToken` helper."""
    pair = pair or generate_ed25519()
    fp = fingerprint if fingerprint is not None else fingerprint_pem(pair.public_key_pem)

    payload: dict[str, Any] = {
        "v": v,
        "fingerprint": fp,
        "publicKeyPem": pair.public_key_pem,
        "timestamp": timestamp if timestamp is not None else now_ms(),
        "nonce": nonce if nonce is not None else random_hex(16),
    }
    if owner is not ...:
        payload["owner"] = owner
    if extra_fields:
        payload.update(extra_fields)

    if skip_sign:
        payload["sig"] = override_sig if override_sig is not None else "invalid"
    else:
        canonical = canonical_json(payload)
        sig = sign_ed25519_b64url(canonical, pair.private_key_pem)
        payload["sig"] = override_sig if override_sig is not None else sig

    return b64url(json.dumps(payload).encode("utf-8"))


def build_jwt(payload: dict[str, Any], priv: rsa.RSAPrivateKey, kid: str) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    h = b64url(json.dumps(header).encode("utf-8"))
    p = b64url(json.dumps(payload).encode("utf-8"))
    sig = sign_rs256(f"{h}.{p}".encode("ascii"), priv)
    return f"{h}.{p}.{b64url(sig)}"


@dataclass
class FullChainBuild:
    token_b64: str
    jwks: dict[str, Any]
    agent_keys: Ed25519Pair
    rsa: RsaPair
    owner: str
    fp: str


def build_full_chain_token(
    *,
    agent_keys: Ed25519Pair | None = None,
    rsa: RsaPair | None = None,
    rsa_kid: str = "test-kid",
    owner: str = "00000003010000000000539c741e0df8",
    owner_session_proof: dict[str, Any] | None = ...,  # type: ignore[assignment]
    id_token_payload_overrides: dict[str, Any] | None = None,
    binding_payload_overrides: dict[str, Any] | None = None,
    binding_signature_override: str | None = None,
    id_token_override: str | None = None,
    id_token_hash_override: str | None = None,
    omit_owner_binding: bool = False,
    omit_id_token: bool = False,
    omit_owner: bool = False,
    omit_cnf: bool = False,
    timestamp: int | None = None,
) -> FullChainBuild:
    agent_keys = agent_keys or generate_ed25519()
    rsa = rsa or generate_rsa()
    fp = fingerprint_pem(agent_keys.public_key_pem)

    # Default `cnf.jkt` binds the id_token to the agent key per RFC 7800
    # §3.1 / RFC 9449 §6.1; the verifier rejects tokens that lack it.
    # Tests can drop the claim with `omit_cnf` or override via
    # `id_token_payload_overrides["cnf"]` to reach the binding failure
    # modes.
    id_token_payload: dict[str, Any] = {
        "iss": "https://sso.alien-api.com",
        "sub": owner,
        "aud": "test-provider",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    if not omit_cnf:
        id_token_payload["cnf"] = {"jkt": ed25519_thumbprint(agent_keys.public_key_pem)}
    if id_token_payload_overrides:
        id_token_payload.update(id_token_payload_overrides)
    id_token = id_token_override or build_jwt(id_token_payload, rsa.private_key, rsa_kid)

    proof: dict[str, Any] | None = None
    if owner_session_proof is not ...:
        proof = owner_session_proof  # type: ignore[assignment]

    binding_payload: dict[str, Any] = {
        "version": 1,
        "issuedAt": now_ms(),
        "issuer": "https://sso.alien-api.com",
        "providerAddress": "test-provider",
        "ownerSessionSub": owner,
        "ownerAudience": "test-provider",
        "idTokenHash": id_token_hash_override or sha256_hex(id_token),
        "ownerSessionProof": proof,
        "ownerSessionProofHash": sha256_hex(canonical_json(proof)) if proof else None,
        "agentInstance": {
            "hostname": "test-host",
            "publicKeyFingerprint": fp,
            "publicKeyPem": agent_keys.public_key_pem,
        },
    }
    if binding_payload_overrides:
        binding_payload.update(binding_payload_overrides)

    binding_canonical = canonical_json(binding_payload)
    binding_payload_hash = sha256_hex(binding_canonical)
    binding_signature = binding_signature_override or sign_ed25519_b64url(
        binding_canonical, agent_keys.private_key_pem
    )
    owner_binding = {
        "id": random_hex(16),
        "payload": binding_payload,
        "payloadHash": binding_payload_hash,
        "signature": binding_signature,
        "createdAt": now_ms(),
    }

    core_payload: dict[str, Any] = {
        "v": 1,
        "fingerprint": fp,
        "publicKeyPem": agent_keys.public_key_pem,
        "timestamp": timestamp if timestamp is not None else now_ms(),
        "nonce": random_hex(16),
    }
    if not omit_owner:
        core_payload["owner"] = owner

    sig = sign_ed25519_b64url(canonical_json(core_payload), agent_keys.private_key_pem)
    full_payload = {**core_payload, "sig": sig}
    if not omit_owner_binding:
        full_payload["ownerBinding"] = owner_binding
    if not omit_id_token:
        full_payload["idToken"] = id_token

    token_b64 = b64url(json.dumps(full_payload).encode("utf-8"))
    jwks = {
        "keys": [
            {**rsa.jwk, "kty": "RSA", "kid": rsa_kid, "use": "sig", "alg": "RS256"}
        ]
    }
    return FullChainBuild(token_b64, jwks, agent_keys, rsa, owner, fp)
