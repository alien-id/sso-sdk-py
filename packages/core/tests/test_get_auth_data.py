"""`get_auth_data()` is now signature-verifying (OIDC §3.1.3.7 / RFC 7519
§7.2). These tests cover the typ + cross-JWT-confusion + opacity rules
that the verifier still enforces, with real RS256 signatures.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from alien_sso import AlienSsoClient, AlienSsoClientConfig, MemoryStorage

PROVIDER = "0xProvider"
ISSUER = "https://sso.test"  # matches sso_base_url for the verifier path


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture
def rsa_pair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    n = pub.public_numbers().n
    e = pub.public_numbers().e
    n_b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_b = e.to_bytes((e.bit_length() + 7) // 8, "big")
    jwk = {
        "kty": "RSA",
        "kid": "k1",
        "alg": "RS256",
        "use": "sig",
        "n": _b64(n_b),
        "e": _b64(e_b),
    }
    return priv, jwk


def _sign_jwt(header: dict, payload: dict, priv: rsa.RSAPrivateKey) -> str:
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    sig = priv.sign(f"{h}.{p}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64(sig)}"


@pytest.fixture
async def client(rsa_pair):
    priv, jwk = rsa_pair
    cfg = AlienSsoClientConfig(sso_base_url=ISSUER, provider_address=PROVIDER)
    c = AlienSsoClient(cfg, storage=MemoryStorage())
    c._jwks_cache.inject({"keys": [jwk]})
    yield c, priv
    await c.aclose()


def _base_payload() -> dict:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "sub": "user-1",
        "aud": PROVIDER,
        "exp": now + 3600,
        "iat": now,
    }


async def test_decodes_id_token_oidc_typ_jwt(client):
    """OIDC §3.1.3.7 id_token: alg=RS256, typ=JWT, single-string aud."""
    c, priv = client
    tok = _sign_jwt({"alg": "RS256", "typ": "JWT", "kid": "k1"}, _base_payload(), priv)
    c._storage.set("alien-sso_id_token", tok)

    claims = c.get_auth_data()
    assert claims is not None
    assert claims.sub == "user-1"


async def test_accepts_id_token_with_application_jwt_long_form(client):
    """RFC 7515 §4.1.9: typ values without `/` MUST be treated as if
    `application/` were prepended."""
    c, priv = client
    tok = _sign_jwt(
        {"alg": "RS256", "typ": "application/jwt", "kid": "k1"}, _base_payload(), priv
    )
    c._storage.set("alien-sso_id_token", tok)

    claims = c.get_auth_data()
    assert claims is not None
    assert claims.sub == "user-1"


async def test_accepts_id_token_with_case_variant_typ(client):
    """RFC 6838 §4.2: media-type comparisons are case-insensitive."""
    c, priv = client
    tok = _sign_jwt({"alg": "RS256", "typ": "JwT", "kid": "k1"}, _base_payload(), priv)
    c._storage.set("alien-sso_id_token", tok)

    claims = c.get_auth_data()
    assert claims is not None


async def test_returns_none_when_only_access_token_present(client):
    """RFC 9068 §6: 'The client MUST NOT inspect the content of the access
    token.' get_auth_data MUST refuse to decode an AT, even when no id_token
    is stored."""
    c, priv = client
    at_payload = {**_base_payload(), "aud": [PROVIDER, ISSUER], "jti": "u-1", "client_id": PROVIDER}
    at = _sign_jwt({"alg": "RS256", "typ": "at+jwt", "kid": "k1"}, at_payload, priv)
    c._storage.set("alien-sso_access_token", at)

    assert c.get_auth_data() is None


async def test_rejects_id_token_carrying_at_jwt_typ(client):
    """RFC 9068 §5 (cross-JWT confusion mitigation): if an attacker stuffs
    an AT (typ=at+jwt) into the id_token slot, get_auth_data MUST reject."""
    c, priv = client
    at_payload = {**_base_payload(), "aud": [PROVIDER, ISSUER]}
    bad = _sign_jwt({"alg": "RS256", "typ": "at+jwt", "kid": "k1"}, at_payload, priv)
    c._storage.set("alien-sso_id_token", bad)

    assert c.get_auth_data() is None


async def test_returns_none_when_no_token_present(client):
    c, _ = client
    assert c.get_auth_data() is None


async def test_rejects_id_token_with_crit_header(client):
    """RFC 7515 §4.1.11: any unrecognised critical header MUST cause
    rejection."""
    c, priv = client
    header = {"alg": "RS256", "typ": "JWT", "kid": "k1", "crit": ["my-ext"], "my-ext": "v"}
    bad = _sign_jwt(header, _base_payload(), priv)
    c._storage.set("alien-sso_id_token", bad)

    assert c.get_auth_data() is None
