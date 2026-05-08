"""RFC 6749 §10.12 / §4.1.1 — OAuth `state` correlation.

The Alien polling design reduces direct CSRF risk because the client never
returns to a redirect URI; the authorization response comes back on
`/oauth/poll`. We still send `state` so that, when the AS echoes it on the
authorize or poll response, the client can verify the round-trip.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import pytest
import respx

from alien_sso import AlienSsoClient, AlienSsoClientConfig, MemoryStorage
from alien_sso.errors import PollError

SSO_BASE_URL = "https://sso.test"
PROVIDER = "00000001000000000000000000000000"


@pytest.fixture
async def client():
    cfg = AlienSsoClientConfig(sso_base_url=SSO_BASE_URL, provider_address=PROVIDER)
    c = AlienSsoClient(cfg, storage=MemoryStorage())
    yield c
    await c.aclose()


async def test_authorize_url_contains_state(client):
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
        resp = await client.generate_deeplink()

    qs = parse_qs(urlparse(captured["url"]).query)
    assert "state" in qs and len(qs["state"][0]) >= 32
    assert resp.state == qs["state"][0]


async def test_authorize_response_state_mismatch_rejected(client):
    # RFC 6749 §10.12: when the AS echoes `state` on the authorize
    # response, it MUST equal what the client sent.
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
                "state": "tampered",
            }
        )
        with pytest.raises(Exception) as exc:
            await client.generate_deeplink()
        assert "state" in str(exc.value).lower()


async def test_poll_state_mismatch_rejected(client):
    # When the poll response carries `state`, it MUST equal what was sent.
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        resp = await client.generate_deeplink()

        router.post("/oauth/poll").respond(
            json={
                "status": "authorized",
                "authorization_code": "ac1",
                "state": "different-from-original",
            }
        )
        with pytest.raises(PollError):
            await client.poll_auth(resp.polling_code, expected_state=resp.state)


async def test_poll_state_match_accepted(client):
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        resp = await client.generate_deeplink()

        router.post("/oauth/poll").respond(
            json={
                "status": "authorized",
                "authorization_code": "ac1",
                "state": resp.state,
            }
        )
        poll = await client.poll_auth(resp.polling_code, expected_state=resp.state)
        assert poll.authorization_code == "ac1"


async def test_poll_without_expected_state_allows_any_response(client):
    # Legacy: AS may not echo state. When the caller does not pass
    # expected_state, the response state field is ignored.
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        await client.generate_deeplink()

        router.post("/oauth/poll").respond(
            json={"status": "pending"}
        )
        poll = await client.poll_auth("p")
        assert poll.authorization_code is None


async def test_poll_rejects_iss_response_param_mismatch(client):
    # RFC 9207 §2.4: when the AS includes `iss` on the poll response,
    # the Client MUST verify it identifies the expected issuer. A
    # mix-up attacker that relays one AS's authorization_code through
    # another is detected here.
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        resp = await client.generate_deeplink()

        router.post("/oauth/poll").respond(
            json={
                "status": "authorized",
                "authorization_code": "ac1",
                "state": resp.state,
                "iss": "https://attacker.example",
            }
        )
        with pytest.raises(PollError, match="9207"):
            await client.poll_auth(resp.polling_code, expected_state=resp.state)


async def test_poll_accepts_iss_response_param_match(client):
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        resp = await client.generate_deeplink()

        router.post("/oauth/poll").respond(
            json={
                "status": "authorized",
                "authorization_code": "ac1",
                "state": resp.state,
                "iss": SSO_BASE_URL,
            }
        )
        poll = await client.poll_auth(resp.polling_code, expected_state=resp.state)
        assert poll.authorization_code == "ac1"


async def test_poll_tolerates_missing_iss_response_param(client):
    # RFC 9207 deployment is incremental — AS implementations that have
    # not yet advertised `authorization_response_iss_parameter_supported`
    # do not include `iss`. Missing iss is therefore tolerated.
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        resp = await client.generate_deeplink()

        router.post("/oauth/poll").respond(
            json={
                "status": "authorized",
                "authorization_code": "ac1",
                "state": resp.state,
            }
        )
        poll = await client.poll_auth(resp.polling_code, expected_state=resp.state)
        assert poll.authorization_code == "ac1"


async def test_poll_with_expected_state_rejects_missing_state(client):
    # RFC 6749 §10.12: when the client retained `state` and is asking
    # the verifier to enforce it, a poll response that omits `state`
    # MUST be rejected — silently passing it would let an attacker-
    # controlled response carrying a forged authorization_code through.
    with respx.mock(base_url=SSO_BASE_URL, assert_all_called=False) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p",
                "expired_at": int(time.time()) + 60,
            }
        )
        resp = await client.generate_deeplink()

        router.post("/oauth/poll").respond(
            json={
                "status": "authorized",
                "authorization_code": "ac1",
                # state omitted on purpose
            }
        )
        with pytest.raises(PollError, match="missing state"):
            await client.poll_auth(resp.polling_code, expected_state=resp.state)
