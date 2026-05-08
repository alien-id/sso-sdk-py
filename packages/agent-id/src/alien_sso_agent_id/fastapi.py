"""FastAPI dependencies for AgentID auth.

Optional — only import this if you've installed the `fastapi` extra:

    pip install "alien-sso-agent-id[fastapi]"

Example:

    from fastapi import Depends, FastAPI
    from alien_sso_agent_id import AgentIdentity, fetch_alien_jwks
    from alien_sso_agent_id.fastapi import build_require_agent

    app = FastAPI()
    JWKS = fetch_alien_jwks()
    require_agent = build_require_agent(jwks=JWKS, owner_required=True)

    @app.get("/me")
    def me(ident: AgentIdentity = Depends(require_agent)):
        return {"fingerprint": ident.fingerprint, "owner": ident.owner}
"""

from __future__ import annotations

from typing import Callable, Optional, Union

try:
    from fastapi import Header, HTTPException
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "FastAPI is not installed. Install with: pip install 'alien-sso-agent-id[fastapi]'"
    ) from e

from alien_sso_agent_id.types import (
    AgentIdentity,
    JWKS,
    VerifyFailure,
    VerifyOwnerOptions,
    VerifyOwnerSuccess,
    VerifyOptions,
    VerifySuccess,
)
from alien_sso_agent_id.verify import (
    verify_agent_token,
    verify_agent_token_with_owner,
)


def build_require_agent(
    *,
    jwks: Optional[JWKS] = None,
    owner_required: bool = False,
    max_age_ms: int = 5 * 60 * 1000,
    clock_skew_ms: int = 30 * 1000,
    expected_issuer: Optional[str] = None,
    expected_audience: Optional[Union[str, list[str]]] = None,
) -> Callable[..., AgentIdentity]:
    """Build a FastAPI dependency that verifies the AgentID token on each request.

    If `jwks` is given, full owner-chain verification runs and `expected_issuer`
    + `expected_audience` are REQUIRED (RFC 7519 §4.1.1 / §4.1.3). If
    `owner_required` is True, requests from agents without a verified human
    owner are rejected with 403.
    """
    if jwks is not None and (expected_issuer is None or expected_audience is None):
        raise ValueError(
            "build_require_agent: when jwks is provided, expected_issuer and "
            "expected_audience are required (RFC 7519 §4.1.1 / §4.1.3)"
        )

    def _require_agent(authorization: Optional[str] = Header(default=None)) -> AgentIdentity:
        if not authorization or not authorization.startswith("AgentID "):
            raise HTTPException(
                status_code=401,
                detail="missing Authorization: AgentID <token> header",
                headers={"WWW-Authenticate": "AgentID"},
            )
        token = authorization[len("AgentID "):].strip()

        if jwks is not None:
            assert expected_issuer is not None and expected_audience is not None
            result = verify_agent_token_with_owner(
                token,
                VerifyOwnerOptions(
                    jwks=jwks,
                    expected_issuer=expected_issuer,
                    expected_audience=expected_audience,
                    max_age_ms=max_age_ms,
                    clock_skew_ms=clock_skew_ms,
                ),
            )
        else:
            result = verify_agent_token(
                token,
                VerifyOptions(max_age_ms=max_age_ms, clock_skew_ms=clock_skew_ms),
            )

        if isinstance(result, VerifyFailure):
            # RFC 6750 §3 / §3.1: a 401 for invalid credentials MUST carry
            # a WWW-Authenticate challenge identifying the auth-scheme and
            # SHOULD include `error="invalid_token"`. The missing-token
            # branch above emits the bare scheme; this is the bad-credentials
            # arm.
            raise HTTPException(
                status_code=401,
                detail=result.error,
                headers={"WWW-Authenticate": 'AgentID error="invalid_token"'},
            )

        if isinstance(result, VerifyOwnerSuccess):
            ident = AgentIdentity(
                fingerprint=result.fingerprint,
                owner=result.owner,
                public_key_pem=result.public_key_pem,
                owner_verified=True,
            )
        else:
            assert isinstance(result, VerifySuccess)
            ident = AgentIdentity(
                fingerprint=result.fingerprint,
                owner=result.owner,
                public_key_pem=result.public_key_pem,
                owner_verified=result.owner_verified,
            )

        if owner_required and not ident.owner:
            raise HTTPException(
                status_code=403,
                detail=(
                    "agent must be owner-bound (verify your Alien Agent ID with a human owner)"
                ),
                headers={"WWW-Authenticate": "AgentID"},
            )
        return ident

    return _require_agent
