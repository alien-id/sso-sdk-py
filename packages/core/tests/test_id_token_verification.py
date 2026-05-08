"""OIDC §3.1.3.7 / RFC 7519 §7.2 — get_auth_data() now signature-verifies."""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from alien_sso import AlienSsoClient, AlienSsoClientConfig, MemoryStorage

PROVIDER = "00000001000000000000000000000000"
ISSUER = "https://sso.test"  # matches sso_base_url for the verifier path


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


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
        "n": _b64u(n_b),
        "e": _b64u(e_b),
    }
    return priv, jwk


def _sign_jwt(payload: dict, header: dict, priv: rsa.RSAPrivateKey) -> str:
    h = _b64u(json.dumps(header).encode())
    p = _b64u(json.dumps(payload).encode())
    sig = priv.sign(f"{h}.{p}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64u(sig)}"


@pytest.fixture
async def client_with_jwks(rsa_pair):
    priv, jwk = rsa_pair
    cfg = AlienSsoClientConfig(sso_base_url=ISSUER, provider_address=PROVIDER)
    c = AlienSsoClient(cfg, storage=MemoryStorage())
    # Test seam: inject the JWKS so we don't need HTTP.
    c._jwks_cache.inject({"keys": [jwk]})
    yield c, priv
    await c.aclose()


def _payload(**override) -> dict:
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "sub": "user-1",
        "aud": PROVIDER,
        "exp": now + 3600,
        "iat": now,
    }
    base.update(override)
    return base


async def test_accepts_signed_id_token(client_with_jwks):
    c, priv = client_with_jwks
    tok = _sign_jwt(_payload(), {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    c._storage.set("alien-sso_id_token", tok)
    claims = c.get_auth_data()
    assert claims is not None
    assert claims.sub == "user-1"


async def test_rejects_tampered_signature(client_with_jwks):
    c, priv = client_with_jwks
    tok = _sign_jwt(_payload(), {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    h, p, s = tok.split(".")
    # Flip a middle char (avoid trailing chars whose low bits are unused
    # padding bits in base64url and could decode unchanged).
    mid = len(s) // 2
    bad_char = "A" if s[mid] != "A" else "B"
    bad_s = s[:mid] + bad_char + s[mid + 1:]
    c._storage.set("alien-sso_id_token", f"{h}.{p}.{bad_s}")
    assert c.get_auth_data() is None


async def test_rejects_expired_id_token(client_with_jwks):
    c, priv = client_with_jwks
    expired = _payload(exp=int(time.time()) - 3600)
    tok = _sign_jwt(expired, {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_id_token_signed_by_wrong_key(client_with_jwks):
    c, _ = client_with_jwks
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tok = _sign_jwt(_payload(), {"alg": "RS256", "typ": "JWT", "kid": "k1"}, other)
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_wrong_issuer(client_with_jwks):
    c, priv = client_with_jwks
    tok = _sign_jwt(
        _payload(iss="https://attacker.example"),
        {"alg": "RS256", "typ": "JWT", "kid": "k1"},
        priv,
    )
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_future_nbf(client_with_jwks):
    c, priv = client_with_jwks
    tok = _sign_jwt(
        _payload(nbf=int(time.time()) + 3600),
        {"alg": "RS256", "typ": "JWT", "kid": "k1"},
        priv,
    )
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_id_token_with_extra_untrusted_audience(client_with_jwks):
    # OIDC §3.1.3.7 step 3: "The ID Token MUST be rejected ... if it
    # contains additional audiences not trusted by the Client."
    c, priv = client_with_jwks
    tok = _sign_jwt(
        _payload(aud=[PROVIDER, "attacker-rp"], azp=PROVIDER),
        {"alg": "RS256", "typ": "JWT", "kid": "k1"},
        priv,
    )
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_accepts_id_token_with_only_expected_audience_in_list(client_with_jwks):
    c, priv = client_with_jwks
    tok = _sign_jwt(
        _payload(aud=[PROVIDER]),
        {"alg": "RS256", "typ": "JWT", "kid": "k1"},
        priv,
    )
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is not None


async def test_rejects_jwe_compact_serialization(client_with_jwks):
    # OIDC §3.1.3.7 / RFC 7516 §9: a 5-part compact serialization is a
    # JWE; we don't support decryption — reject explicitly.
    c, _ = client_with_jwks
    c._storage.set("alien-sso_id_token", "a.b.c.d.e")
    assert c.get_auth_data() is None


async def test_rejects_jws_with_enc_header(client_with_jwks):
    # RFC 7516 §4.1.2: `enc` is JWE-only. Treat its presence in a JWS-shaped
    # token as an Encrypted-ID-Token policy violation.
    c, priv = client_with_jwks
    tok = _sign_jwt(
        _payload(),
        {"alg": "RS256", "enc": "A256GCM", "typ": "JWT", "kid": "k1"},
        priv,
    )
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_crit_header_in_signed_path(client_with_jwks):
    c, priv = client_with_jwks
    tok = _sign_jwt(
        _payload(),
        {"alg": "RS256", "typ": "JWT", "kid": "k1", "crit": ["x"], "x": 1},
        priv,
    )
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_id_token_with_string_nbf(client_with_jwks):
    # RFC 7519 §4.1.5: nbf MUST be a NumericDate. A non-numeric value is
    # malformed and MUST cause rejection — silently ignoring it lets an
    # attacker bypass the not-before check by sending a string.
    c, priv = client_with_jwks
    p = _payload()
    p["nbf"] = "not-a-number"
    tok = _sign_jwt(p, {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_id_token_with_bool_nbf(client_with_jwks):
    c, priv = client_with_jwks
    p = _payload()
    p["nbf"] = True
    tok = _sign_jwt(p, {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_id_token_with_string_iat(client_with_jwks):
    # RFC 7519 §4.1.6: iat, when present, MUST be a NumericDate. The
    # verifier rejects non-numeric values rather than letting the schema
    # layer be the only line of defense.
    c, priv = client_with_jwks
    p = _payload()
    p["iat"] = "not-a-number"
    tok = _sign_jwt(p, {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_rejects_id_token_with_bool_iat(client_with_jwks):
    # bool is a subtype of int in Python — a naïve isinstance(iat, (int, float))
    # would let `True` through. Defense against accidental coercion.
    c, priv = client_with_jwks
    p = _payload()
    p["iat"] = True
    tok = _sign_jwt(p, {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_skips_jwk_marked_use_enc(rsa_pair):
    # RFC 7517 §4.2: a JWK with use=enc is encryption-only and MUST NOT
    # be selected for JWS verification, even if kid+alg match. The verifier
    # should walk past it (and find no other key) → reject.
    priv, jwk = rsa_pair
    enc_only = {**jwk, "use": "enc"}
    cfg = AlienSsoClientConfig(sso_base_url=ISSUER, provider_address=PROVIDER)
    c = AlienSsoClient(cfg, storage=MemoryStorage())
    c._jwks_cache.inject({"keys": [enc_only]})
    tok = _sign_jwt(_payload(), {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None
    await c.aclose()


async def test_rejects_multi_audience_id_token_without_azp(client_with_jwks):
    # OIDC §3.1.3.7 step 4: multi-audience id_tokens MUST carry azp so
    # the authorized party is unambiguous. Without azp, reject.
    c, priv = client_with_jwks
    tok = _sign_jwt(
        _payload(aud=[PROVIDER, PROVIDER + "-other"], **{}),
        {"alg": "RS256", "typ": "JWT", "kid": "k1"},
        priv,
    )
    c._storage.set("alien-sso_id_token", tok)
    assert c.get_auth_data() is None


async def test_accepts_multi_audience_id_token_with_correct_azp(client_with_jwks):
    # When all extra audiences are trusted (caller widened the set) AND
    # azp is present and equals the expected audience, the multi-aud
    # token is accepted.
    c, priv = client_with_jwks
    extra = PROVIDER + "-trusted"
    tok = _sign_jwt(
        _payload(aud=[PROVIDER, extra], azp=PROVIDER),
        {"alg": "RS256", "typ": "JWT", "kid": "k1"},
        priv,
    )
    c._storage.set("alien-sso_id_token", tok)
    # widen trusted set via the underlying verifier
    from alien_sso._verify import verify_id_token
    result = verify_id_token(
        tok,
        jwks=c._jwks_cache.get(),
        expected_issuer=ISSUER,
        expected_audience=PROVIDER,
        expected_nonce=None,
        trusted_audiences={PROVIDER, extra},
    )
    assert result is not None


async def test_selects_jwk_with_use_sig_when_use_enc_sibling_present(rsa_pair):
    # When the JWKS lists both an enc-only and a sig-only key under
    # different kids, the sig-only key MUST be the one that verifies.
    priv, jwk = rsa_pair
    sig_key = {**jwk, "kid": "k1", "use": "sig"}
    # Same n/e, different kid+use — the verifier must skip this one.
    enc_sibling = {**jwk, "kid": "k1-enc", "use": "enc"}
    cfg = AlienSsoClientConfig(sso_base_url=ISSUER, provider_address=PROVIDER)
    c = AlienSsoClient(cfg, storage=MemoryStorage())
    c._jwks_cache.inject({"keys": [enc_sibling, sig_key]})
    tok = _sign_jwt(_payload(), {"alg": "RS256", "typ": "JWT", "kid": "k1"}, priv)
    c._storage.set("alien-sso_id_token", tok)
    claims = c.get_auth_data()
    assert claims is not None
    assert claims.sub == "user-1"
    await c.aclose()
