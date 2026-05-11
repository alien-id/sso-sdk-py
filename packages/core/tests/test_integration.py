"""Port of `packages/core/tests/integration/sso.integration.test.ts`.

Uses `respx` to intercept httpx requests rather than running a real server
(matches the JS approach with `nock`).
"""

from __future__ import annotations

import asyncio
import base64
import json
import time

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from alien_sso import (
    AlienSsoClient,
    AlienSsoClientConfig,
    MemoryStorage,
    PollStatus,
)

SSO_BASE_URL = "https://sso.test"
ISSUER = "https://sso.alien-api.com"
PROVIDER_ADDRESS = "00000001000000000000000000000000"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUB_NUMS = _PRIV.public_key().public_numbers()
_JWK = {
    "kty": "RSA",
    "kid": "k1",
    "alg": "RS256",
    "use": "sig",
    "n": _b64url(_PUB_NUMS.n.to_bytes((_PUB_NUMS.n.bit_length() + 7) // 8, "big")),
    "e": _b64url(_PUB_NUMS.e.to_bytes((_PUB_NUMS.e.bit_length() + 7) // 8, "big")),
}


def _make_jwt(aud: str, *, nonce: str | None = None) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": "k1"}
    payload: dict = {
        "iss": ISSUER,
        "sub": "session-address-test",
        "aud": aud,
        "exp": now + 3600,
        "iat": now,
    }
    if nonce is not None:
        payload["nonce"] = nonce
    h = _b64url(json.dumps(header).encode("utf-8"))
    p = _b64url(json.dumps(payload).encode("utf-8"))
    sig = _PRIV.sign(f"{h}.{p}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url(sig)}"


@pytest.fixture
def mock_sso():
    """Stub every SSO endpoint we touch in the happy-path flow."""
    from urllib.parse import parse_qs, urlparse

    captured_nonce: dict[str, str | None] = {"nonce": None}

    def _on_authorize(request):
        qs = parse_qs(urlparse(str(request.url)).query)
        captured_nonce["nonce"] = qs.get("nonce", [None])[0]
        return respx.MockResponse(
            json={
                "deep_link": "alienapp://authorize_session",
                "polling_code": "polling-code-test",
                "expired_at": int(time.time()) + 300,
            }
        )

    def _on_token(request):
        return respx.MockResponse(
            json={
                "access_token": _make_jwt(PROVIDER_ADDRESS),
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": _make_jwt(PROVIDER_ADDRESS, nonce=captured_nonce["nonce"]),
                "refresh_token": "refresh-token-test",
            }
        )

    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").mock(side_effect=_on_authorize)
        router.post("/oauth/poll").respond(
            json={"status": "authorized", "authorization_code": "auth-code-test"}
        )
        router.post("/oauth/token").mock(side_effect=_on_token)
        router.get("/oauth/userinfo").respond(json={"sub": "session-address-test"})
        yield router


@pytest.fixture
async def client():
    cfg = AlienSsoClientConfig(
        sso_base_url=SSO_BASE_URL,
        provider_address=PROVIDER_ADDRESS,
        expected_issuer=ISSUER,
    )
    c = AlienSsoClient(cfg, storage=MemoryStorage())
    c._jwks_cache.inject({"keys": [_JWK]})
    yield c
    await c.aclose()


async def test_full_sso_flow(mock_sso, client):
    auth = await client.generate_deeplink()
    assert auth.deep_link
    assert auth.polling_code
    assert isinstance(auth.expired_at, int)

    poll = await client.poll_auth(auth.polling_code)
    assert poll.status == PollStatus.AUTHORIZED
    assert poll.authorization_code

    token = await client.exchange_token(poll.authorization_code)
    assert token.access_token
    assert token.token_type == "Bearer"
    assert token.id_token
    assert token.refresh_token == "refresh-token-test"

    info = await client.verify_auth()
    assert info is not None
    assert info.sub == "session-address-test"

    parsed = client.get_auth_data()
    assert parsed is not None
    assert parsed.sub == "session-address-test"
    assert parsed.aud == PROVIDER_ADDRESS

    assert client.get_subject() == "session-address-test"
    assert client.is_token_expired() is False


async def test_logout_clears_tokens(mock_sso, client):
    auth = await client.generate_deeplink()
    poll = await client.poll_auth(auth.polling_code)
    await client.exchange_token(poll.authorization_code)

    client.logout()
    assert client.get_access_token() is None
    assert client.get_id_token() is None
    assert client.get_auth_data() is None
    assert client.get_refresh_token() is None


async def test_verify_auth_returns_none_with_no_token(client):
    assert await client.verify_auth() is None


async def test_get_auth_data_rejects_audience_mismatch(mock_sso, client):
    """A token whose `aud` does not include this provider is silently rejected."""
    other_aud_token = _make_jwt("some-other-provider")
    client._storage.set("alien-sso_id_token", other_aud_token)
    assert client.get_auth_data() is None


async def test_verify_auth_rejects_userinfo_aud_mismatch(client):
    # OIDC §5.3: when the userinfo response carries `aud`, it MUST
    # identify this client. A response advertising aud=`some-other-rp`
    # signals AT-substitution and the client MUST reject.
    from alien_sso.errors import UnauthorizedError

    client._storage.set("alien-sso_access_token", "at-1")
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/userinfo").respond(
            json={"sub": "user-1", "aud": "some-other-rp"}
        )
        with pytest.raises(UnauthorizedError, match="aud"):
            await client.verify_auth()


async def test_verify_auth_accepts_userinfo_aud_matching_client_id(client):
    client._storage.set("alien-sso_access_token", "at-1")
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/userinfo").respond(
            json={"sub": "user-1", "aud": PROVIDER_ADDRESS}
        )
        info = await client.verify_auth()
        assert info is not None
        assert info.aud == PROVIDER_ADDRESS


async def test_refresh_access_token_fetches_new_tokens(client):
    client._storage.set("alien-sso_refresh_token", "stale-refresh")
    new = {
        "access_token": _make_jwt(PROVIDER_ADDRESS),
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "new-refresh",
    }
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.post("/oauth/token").respond(json=new)
        token = await client.refresh_access_token()
    assert token.refresh_token == "new-refresh"
    assert client.get_refresh_token() == "new-refresh"


async def test_refresh_clears_tokens_on_failure(client):
    client._storage.set("alien-sso_refresh_token", "stale-refresh")
    client._storage.set("alien-sso_access_token", "stale-access")
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.post("/oauth/token").respond(400, json={"error": "invalid_grant"})
        with pytest.raises(Exception):
            await client.refresh_access_token()
    assert client.get_refresh_token() is None
    assert client.get_access_token() is None


async def test_concurrent_refreshes_coalesce(client):
    """Three concurrent refresh_access_token calls should fire ONE network request."""
    client._storage.set("alien-sso_refresh_token", "stale-refresh")
    new = {
        "access_token": _make_jwt(PROVIDER_ADDRESS),
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "new-refresh",
    }
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        route = router.post("/oauth/token").respond(json=new)
        results = await asyncio.gather(
            client.refresh_access_token(),
            client.refresh_access_token(),
            client.refresh_access_token(),
        )
    assert all(r.refresh_token == "new-refresh" for r in results)
    assert route.call_count == 1


async def test_authorize_endpoint_failure_raises(client):
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(500, json={"error": "boom"})
        with pytest.raises(Exception):
            await client.generate_deeplink()


async def test_exchange_token_without_verifier_raises(client):
    # No prior generate_deeplink — verifier is missing
    with pytest.raises(Exception):
        await client.exchange_token("some-code")


async def test_async_context_manager(mock_sso):
    cfg = AlienSsoClientConfig(
        sso_base_url=SSO_BASE_URL,
        provider_address=PROVIDER_ADDRESS,
        expected_issuer=ISSUER,
    )
    async with AlienSsoClient(cfg, storage=MemoryStorage()) as c:
        c._jwks_cache.inject({"keys": [_JWK]})
        auth = await c.generate_deeplink()
        assert auth.polling_code
