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

from alien_sso import (
    AlienSsoClient,
    AlienSsoClientConfig,
    MemoryStorage,
    PollStatus,
)

SSO_BASE_URL = "http://sso.test"
PROVIDER_ADDRESS = "00000001000000000000000000000000"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_jwt(aud: str) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": "https://sso.alien.com",
        "sub": "session-address-test",
        "aud": aud,
        "exp": now + 3600,
        "iat": now,
    }
    h = _b64url(json.dumps(header).encode("utf-8"))
    p = _b64url(json.dumps(payload).encode("utf-8"))
    return f"{h}.{p}.fake-signature"


@pytest.fixture
def mock_sso():
    """Stub every SSO endpoint we touch in the happy-path flow."""
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://authorize_session",
                "polling_code": "polling-code-test",
                "expired_at": int(time.time()) + 300,
            }
        )
        router.post("/oauth/poll").respond(
            json={"status": "authorized", "authorization_code": "auth-code-test"}
        )
        token_payload = {
            "access_token": _make_jwt(PROVIDER_ADDRESS),
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": _make_jwt(PROVIDER_ADDRESS),
            "refresh_token": "refresh-token-test",
        }
        router.post("/oauth/token").respond(json=token_payload)
        router.get("/oauth/userinfo").respond(json={"sub": "session-address-test"})
        yield router


@pytest.fixture
async def client():
    cfg = AlienSsoClientConfig(
        sso_base_url=SSO_BASE_URL, provider_address=PROVIDER_ADDRESS
    )
    c = AlienSsoClient(cfg, storage=MemoryStorage())
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
        sso_base_url=SSO_BASE_URL, provider_address=PROVIDER_ADDRESS
    )
    async with AlienSsoClient(cfg, storage=MemoryStorage()) as c:
        auth = await c.generate_deeplink()
        assert auth.polling_code
