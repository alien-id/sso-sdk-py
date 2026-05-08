"""Render tests — confirm the templates load and produce the expected DOM hooks.

We use a stub client so we don't need a live SSO server for unit tests.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional

import pytest
import respx

from alien_sso import AlienSsoClient, AlienSsoClientConfig, MemoryStorage
from alien_sso_jinja import SsoUi, render_qr_svg


@pytest.fixture
async def client():
    cfg = AlienSsoClientConfig(
        sso_base_url="http://localhost", provider_address="prov-1"
    )
    c = AlienSsoClient(cfg, storage=MemoryStorage())
    yield c
    await c.aclose()


@pytest.fixture
def ui(client):
    return SsoUi(client=client)


# ─── Rendering ────────────────────────────────────────────────────────────


def test_render_button_contains_label(ui):
    html = ui.render_button()
    assert 'data-alien-sso-open="alien-sso-modal"' in html
    assert "Sign in with Alien" in html


def test_render_button_with_custom_label(client):
    ui = SsoUi(client=client, button_label="Connect Alien")
    assert "Connect Alien" in ui.render_button()


def test_render_modal_contains_dialog_role(ui):
    html = ui.render_modal()
    assert 'role="dialog"' in html
    assert 'data-alien-sso-qr' in html
    assert 'data-alien-sso-status' in html


def test_render_assets_contains_api_base_and_polling_interval(client):
    ui = SsoUi(client=client, api_base="/my/sso", polling_interval_ms=2500)
    assets = ui.render_assets()
    assert '"/my/sso"' in assets
    assert "2500" in assets


def test_render_all_includes_button_modal_assets(ui):
    html = ui.render_all()
    assert "<style>" in html
    assert "<script>" in html
    assert 'data-alien-sso-open' in html
    assert 'data-alien-sso-qr' in html


def test_render_qr_svg_returns_svg_string():
    svg = render_qr_svg("alienapp://link/test")
    assert svg.startswith("<svg")
    assert "</svg>" in svg


# ─── Handlers ─────────────────────────────────────────────────────────────


SSO = "http://localhost"


async def test_start_returns_qr_and_polling_code(ui):
    with respx.mock(base_url=SSO) as router:
        router.get("/oauth/authorize").respond(
            json={
                "deep_link": "alienapp://x",
                "polling_code": "p-code",
                "expired_at": int(time.time()) + 300,
            }
        )
        r = await ui.start()
    assert r.status == 200
    assert r.body["ok"] is True
    assert r.body["polling_code"] == "p-code"
    assert "qr_svg" in r.body
    assert r.body["qr_svg"].startswith("<svg")


async def test_start_returns_500_on_upstream_failure(ui):
    with respx.mock(base_url=SSO) as router:
        router.get("/oauth/authorize").respond(500)
        r = await ui.start()
    assert r.status == 500
    assert r.body["ok"] is False


async def test_poll_passes_through_authorized_status(ui):
    with respx.mock(base_url=SSO) as router:
        router.post("/oauth/poll").respond(
            json={"status": "authorized", "authorization_code": "ac-1"}
        )
        r = await ui.poll("p-code")
    assert r.status == 200
    assert r.body["status"] == "authorized"
    assert r.body["authorization_code"] == "ac-1"


async def test_poll_omits_authorization_code_when_pending(ui):
    with respx.mock(base_url=SSO) as router:
        router.post("/oauth/poll").respond(json={"status": "pending"})
        r = await ui.poll("p-code")
    assert r.body["status"] == "pending"
    assert "authorization_code" not in r.body


async def test_poll_returns_400_on_empty_code(ui):
    r = await ui.poll("")
    assert r.status == 400


async def test_finish_exchanges_token_and_returns_subject(ui):
    import base64, json

    def jwt():
        h = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(
            json.dumps({
                "iss": "https://sso.alien.com",
                "sub": "user-1",
                "aud": "prov-1",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            }).encode()
        ).rstrip(b"=").decode()
        return f"{h}.{p}.sig"

    # Pre-populate the verifier (normally generate_deeplink does this)
    ui.client._storage.set("alien-sso_code_verifier", "stored-verifier")

    with respx.mock(base_url=SSO) as router:
        router.post("/oauth/token").respond(
            json={
                "access_token": jwt(),
                "id_token": jwt(),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "r1",
            }
        )
        r = await ui.finish("ac-1")
    assert r.status == 200
    assert r.body["sub"] == "user-1"


async def test_finish_returns_400_on_empty_code(ui):
    r = await ui.finish("")
    assert r.status == 400
