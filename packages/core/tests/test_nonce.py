"""OIDC Core §3.1.3.7.11 / .12 — nonce send + replay validation."""

from __future__ import annotations

import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from alien_sso import AlienSsoClient, AlienSsoClientConfig, MemoryStorage

SSO_BASE_URL = "https://sso.test"
ISSUER = "https://sso.alien-api.com"
PROVIDER = "00000001000000000000000000000000"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUB_NUMS = _PRIV.public_key().public_numbers()
_JWK = {
    "kty": "RSA",
    "kid": "k1",
    "alg": "RS256",
    "use": "sig",
    "n": _b64(_PUB_NUMS.n.to_bytes((_PUB_NUMS.n.bit_length() + 7) // 8, "big")),
    "e": _b64(_PUB_NUMS.e.to_bytes((_PUB_NUMS.e.bit_length() + 7) // 8, "big")),
}


def _make_id_token(*, nonce: str | None, aud: str = PROVIDER) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": "k1"}
    payload: dict = {
        "iss": ISSUER,
        "sub": "u1",
        "aud": aud,
        "exp": now + 3600,
        "iat": now,
    }
    if nonce is not None:
        payload["nonce"] = nonce
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    sig = _PRIV.sign(f"{h}.{p}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64(sig)}"


@pytest.fixture
async def client():
    cfg = AlienSsoClientConfig(
        sso_base_url=SSO_BASE_URL, provider_address=PROVIDER, expected_issuer=ISSUER
    )
    c = AlienSsoClient(cfg, storage=MemoryStorage())
    c._jwks_cache.inject({"keys": [_JWK]})
    yield c
    await c.aclose()


async def test_authorize_url_contains_nonce(client):
    """OIDC §3.1.2.1: client MAY/SHOULD send `nonce` in authorization request."""
    captured: dict = {}

    def _capture(request):
        captured["url"] = str(request.url)
        return respx.MockResponse(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )

    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").mock(side_effect=_capture)
        await client.generate_deeplink()

    qs = parse_qs(urlparse(captured["url"]).query)
    assert "nonce" in qs and len(qs["nonce"][0]) >= 32


async def test_get_auth_data_accepts_matching_nonce(client):
    """OIDC §3.1.3.7.11: id_token nonce MUST equal the persisted request nonce."""
    # Run authorize to mint+persist nonce.
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        await client.generate_deeplink()

    nonce = client._storage.get("alien-sso_nonce")
    assert nonce
    client._storage.set("alien-sso_id_token", _make_id_token(nonce=nonce))
    assert client.get_auth_data() is not None


async def test_get_auth_data_rejects_mismatched_nonce(client):
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        await client.generate_deeplink()

    client._storage.set("alien-sso_id_token", _make_id_token(nonce="attacker-replay"))
    assert client.get_auth_data() is None


async def test_nonce_consumed_on_first_successful_use(client):
    # OIDC §3.1.3.7.11: nonce is for replay detection. After a successful
    # match, the nonce MUST be consumed in the shared store so that a
    # second client (different process / re-init) cannot validate the same
    # id_token. Repeated reads inside the SAME client return the cached
    # verified payload — no double-consume — which is the expected UX.
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        await client.generate_deeplink()

    nonce = client._storage.get("alien-sso_nonce")
    assert nonce
    tok = _make_id_token(nonce=nonce)
    client._storage.set("alien-sso_id_token", tok)
    # First call succeeds and consumes the nonce in the shared store.
    assert client.get_auth_data() is not None
    # Repeated read on same client → cached → still works.
    assert client.get_auth_data() is not None

    # Simulate a second process: new client, but caller wires a SHARED
    # nonce store (the persistence boundary). The shared store rejects the
    # already-consumed nonce → replay fails.
    cfg = AlienSsoClientConfig(
        sso_base_url=SSO_BASE_URL, provider_address=PROVIDER, expected_issuer=ISSUER
    )
    other = AlienSsoClient(cfg, storage=MemoryStorage())
    other._jwks_cache.inject({"keys": [_JWK]})
    other.set_nonce_store(client._nonce_store)
    other._storage.set("alien-sso_nonce", nonce)
    other._storage.set("alien-sso_id_token", tok)
    assert other.get_auth_data() is None
    await other.aclose()


async def test_custom_nonce_store_consume_callback_invoked(client):
    # Caller-supplied store: receives consume(nonce) → bool. When the store
    # returns False, verification fails (treated as a replay/unknown nonce).
    seen: list[str] = []

    class RejectingStore:
        def consume(self, n: str) -> bool:
            seen.append(n)
            return False

    client.set_nonce_store(RejectingStore())

    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        await client.generate_deeplink()

    nonce = client._storage.get("alien-sso_nonce")
    client._storage.set("alien-sso_id_token", _make_id_token(nonce=nonce))
    assert client.get_auth_data() is None
    assert seen == [nonce]


async def test_get_auth_data_rejects_id_token_missing_nonce_when_request_carried_one(client):
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        await client.generate_deeplink()

    # id_token has no nonce claim, but the request carried one → reject.
    client._storage.set("alien-sso_id_token", _make_id_token(nonce=None))
    assert client.get_auth_data() is None
