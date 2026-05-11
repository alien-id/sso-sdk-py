"""FastAPI dependency wiring — RFC 6750 §3 challenge format on 401s."""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("fastapi.testclient")

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from alien_sso_agent_id.fastapi import build_require_agent
from alien_sso_agent_id.types import AgentIdentity


def _app(**kwargs) -> TestClient:
    require_agent = build_require_agent(**kwargs)
    app = FastAPI()

    @app.get("/me")
    def me(ident: AgentIdentity = Depends(require_agent)):
        return {"fingerprint": ident.fingerprint}

    return TestClient(app, raise_server_exceptions=False)


def test_missing_authorization_returns_401_with_www_authenticate():
    # Pre-existing behaviour: kept for regression.
    client = _app()
    resp = client.get("/me")
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "AgentID"


def test_invalid_token_returns_401_with_invalid_token_challenge():
    # RFC 6750 §3: when the request includes credentials that are not
    # acceptable, the server MUST return a 401 with a WWW-Authenticate
    # header carrying the auth-scheme. RFC 6750 §3.1: invalid token →
    # `error="invalid_token"`. We mirror that for the AgentID scheme.
    client = _app()
    resp = client.get("/me", headers={"Authorization": "AgentID not-a-real-token"})
    assert resp.status_code == 401
    challenge = resp.headers.get("www-authenticate")
    assert challenge is not None
    assert challenge.startswith("AgentID")
    assert 'error="invalid_token"' in challenge


def test_owner_required_403_carries_agentid_challenge():
    # RFC 6750 §3 in spirit: 4xx auth errors should carry a parseable
    # challenge so clients know which scheme to re-authenticate with.
    # AgentID is our custom scheme; 403 from owner_required signals
    # missing-owner, distinct from 401 invalid_token.
    # We still expose the scheme so middleware can react uniformly.
    from conftest import build_token, generate_ed25519

    pair = generate_ed25519()
    # Build a token without owner — verify_agent_token succeeds (no jwks
    # = basic-only) but the FastAPI dep will 403 because owner_required.
    tok = build_token(pair, owner=...)  # ... sentinel = omit owner

    client = _app(owner_required=True)
    resp = client.get("/me", headers={"Authorization": f"AgentID {tok}"})
    assert resp.status_code == 403
    challenge = resp.headers.get("www-authenticate")
    assert challenge is not None
    assert challenge.startswith("AgentID")
