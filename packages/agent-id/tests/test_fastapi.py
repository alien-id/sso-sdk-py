"""FastAPI dependency wiring — RFC 6750 §3 challenge format on 401s."""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("fastapi.testclient")

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from alien_sso_agent_id import VerifyDPoPSuccess
from alien_sso_agent_id.fastapi import build_require_dpop


def _app(**kwargs) -> TestClient:
    require_dpop = build_require_dpop(**kwargs)
    app = FastAPI()

    @app.get("/me")
    def me(auth: VerifyDPoPSuccess = Depends(require_dpop)):
        return {"sub": auth.sub, "jkt": auth.jkt}

    return TestClient(app, raise_server_exceptions=False)


def test_missing_authorization_returns_401_with_dpop_challenge():
    client = _app(jwks={"keys": []})
    resp = client.get("/me")
    assert resp.status_code == 401
    challenge = resp.headers.get("www-authenticate")
    assert challenge is not None
    assert challenge.startswith("DPoP")
    assert 'error="invalid_token"' in challenge


def test_invalid_token_returns_401_with_dpop_challenge():
    # RFC 6750 §3: when the request includes credentials that are not
    # acceptable, the server MUST return a 401 with a WWW-Authenticate
    # header carrying the auth-scheme. RFC 9449 §7.1 keeps the DPoP
    # scheme on the challenge. RFC 6750 §3.1: invalid token →
    # `error="invalid_token"`.
    client = _app(jwks={"keys": []})
    resp = client.get(
        "/me",
        headers={"Authorization": "DPoP not-a-real-token", "DPoP": "also-bogus"},
    )
    assert resp.status_code == 401
    challenge = resp.headers.get("www-authenticate")
    assert challenge is not None
    assert challenge.startswith("DPoP")
    assert 'error="invalid_token"' in challenge
