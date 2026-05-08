"""Tests for the HTTP endpoints + ed25519 verify instruction layout."""

from __future__ import annotations

import struct
import time

import pytest
import respx

from alien_sso_solana import (
    AlienSolanaSsoClient,
    AlienSolanaSsoClientConfig,
    SolanaPollStatus,
)
from alien_sso_solana._ed25519_program import (
    ED25519_PROGRAM_ID,
    create_ed25519_verify_instruction,
)

SSO_BASE_URL = "http://localhost"
PROVIDER = "00000001000000000000000000000000"


@pytest.fixture
async def client():
    cfg = AlienSolanaSsoClientConfig(sso_base_url=SSO_BASE_URL, provider_address=PROVIDER)
    c = AlienSolanaSsoClient(cfg)
    yield c
    await c.aclose()


# ─── HTTP endpoints ───────────────────────────────────────────────────────


async def test_generate_deeplink(client):
    with respx.mock(base_url=SSO_BASE_URL) as router:
        router.post("/solana/link").respond(
            json={
                "deep_link": "alienapp://link",
                "polling_code": "p-code",
                "expired_at": int(time.time()) + 300,
            }
        )
        resp = await client.generate_deeplink("8FXDvWWRkw2W2H7AdNNgrU4UYtGSeMKNrk3LjQXqGGqZ")
    assert resp.deep_link == "alienapp://link"
    assert resp.polling_code == "p-code"


async def test_poll_auth_authorized(client):
    with respx.mock(base_url=SSO_BASE_URL) as router:
        router.post("/solana/poll").respond(
            json={
                "status": "authorized",
                "oracle_signature": "01" * 64,
                "oracle_public_key": "02" * 32,
                "solana_address": "addr",
                "timestamp": 1700000000,
                "session_address": "session-addr",
            }
        )
        resp = await client.poll_auth("p-code")
    assert resp.status == SolanaPollStatus.AUTHORIZED
    assert resp.session_address == "session-addr"


async def test_get_attestation_returns_session_address(client):
    with respx.mock(base_url=SSO_BASE_URL) as router:
        router.post("/solana/attestation").respond(
            json={"session_address": "session-addr"}
        )
        sa = await client.get_attestation("solana-addr")
    assert sa == "session-addr"


async def test_get_attestation_returns_none_on_404(client):
    with respx.mock(base_url=SSO_BASE_URL) as router:
        router.post("/solana/attestation").respond(404)
        sa = await client.get_attestation("solana-addr")
    assert sa is None


async def test_link_failure_raises(client):
    from alien_sso_solana import AlienSolanaSsoError

    with respx.mock(base_url=SSO_BASE_URL) as router:
        router.post("/solana/link").respond(500)
        with pytest.raises(AlienSolanaSsoError):
            await client.generate_deeplink("solana-addr")


async def test_provider_address_header_sent(client):
    with respx.mock(base_url=SSO_BASE_URL) as router:
        route = router.post("/solana/poll").respond(
            json={"status": "pending"}
        )
        await client.poll_auth("p-code")
    sent = route.calls.last.request
    assert sent.headers["x-provider-address"] == PROVIDER


# ─── ed25519 verify instruction layout ────────────────────────────────────


def test_ed25519_verify_instruction_layout():
    pub = bytes(range(32))
    sig = bytes(range(64))
    msg = b"hello world"
    ix = create_ed25519_verify_instruction(public_key=pub, message=msg, signature=sig)

    assert ix.program_id == ED25519_PROGRAM_ID
    assert ix.accounts == []
    data = bytes(ix.data)
    assert data[0] == 1  # num_signatures
    assert data[1] == 0  # padding
    sig_off, sig_idx, pk_off, pk_idx, m_off, m_size, m_idx = struct.unpack_from(
        "<HHHHHHH", data, 2
    )
    assert pk_off == 16
    assert sig_off == 48
    assert m_off == 112
    assert m_size == len(msg)
    assert sig_idx == pk_idx == m_idx == 0xFFFF
    assert data[16:48] == pub
    assert data[48:112] == sig
    assert data[112:] == msg


def test_ed25519_verify_rejects_wrong_size():
    with pytest.raises(ValueError):
        create_ed25519_verify_instruction(public_key=b"too short", message=b"x", signature=b"\0" * 64)
    with pytest.raises(ValueError):
        create_ed25519_verify_instruction(public_key=b"\0" * 32, message=b"x", signature=b"\0" * 10)
