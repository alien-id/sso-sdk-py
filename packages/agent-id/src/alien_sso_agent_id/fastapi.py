"""FastAPI dependency for RFC 9449 DPoP authentication.

Optional — only import this if you've installed the `fastapi` extra:

    pip install "alien-sso-agent-id[fastapi]"

Example:

    from fastapi import Depends, FastAPI, Request
    from alien_sso_agent_id import fetch_alien_jwks, VerifyDPoPSuccess
    from alien_sso_agent_id.fastapi import build_require_dpop

    app = FastAPI()
    JWKS = fetch_alien_jwks()
    require_dpop = build_require_dpop(
        jwks=JWKS,
        expected_audience="my-resource-server",
    )

    @app.get("/me")
    def me(auth: VerifyDPoPSuccess = Depends(require_dpop)):
        return {"sub": auth.sub, "jkt": auth.jkt}
"""

from __future__ import annotations

from typing import Callable, Optional

try:
    from fastapi import HTTPException, Request
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "FastAPI is not installed. Install with: pip install 'alien-sso-agent-id[fastapi]'"
    ) from e

from alien_sso_agent_id.types import (
    JWKS,
    DPoPJtiStore,
    VerifyDPoPFailure,
    VerifyDPoPOptions,
    VerifyDPoPSuccess,
)
from alien_sso_agent_id.verify import verify_dpop_request


def build_require_dpop(
    *,
    jwks: JWKS,
    expected_issuer: Optional[str] = None,
    expected_audience: Optional[str] = None,
    proof_max_age_sec: int = 30,
    clock_skew_sec: int = 30,
    jti_store: Optional[DPoPJtiStore] = None,
) -> Callable[[Request], VerifyDPoPSuccess]:
    """Build a FastAPI dependency that verifies RFC 9449 DPoP on each request.

    On verification failure, raises 401 with an RFC 6750 §3.1-style
    `WWW-Authenticate: DPoP error="invalid_token"` challenge.
    """

    def _require_dpop(request: Request) -> VerifyDPoPSuccess:
        # Convert Starlette's MultiDict-ish Headers into a plain dict with
        # case-insensitive single-value-or-list semantics that
        # verify_dpop_request expects.
        headers: dict[str, object] = {}
        for k, v in request.headers.items():
            existing = headers.get(k.lower())
            if existing is None:
                headers[k.lower()] = v
            elif isinstance(existing, list):
                existing.append(v)
            else:
                headers[k.lower()] = [existing, v]
        req = {
            "method": request.method,
            "url": str(request.url),
            "headers": headers,
        }
        result = verify_dpop_request(
            req,
            VerifyDPoPOptions(
                jwks=jwks,
                expected_issuer=expected_issuer,
                expected_audience=expected_audience,
                proof_max_age_sec=proof_max_age_sec,
                clock_skew_sec=clock_skew_sec,
                jti_store=jti_store,
            ),
        )
        if isinstance(result, VerifyDPoPFailure):
            # RFC 6750 §3 / §3.1: a 401 for invalid credentials MUST carry
            # a WWW-Authenticate challenge identifying the auth-scheme and
            # SHOULD include `error="invalid_token"`. RFC 9449 §7.1 keeps
            # the DPoP scheme on the challenge.
            raise HTTPException(
                status_code=401,
                detail=result.error,
                headers={
                    "WWW-Authenticate": f'DPoP error="invalid_token", error_description="{result.code}"'
                },
            )
        return result

    return _require_dpop
