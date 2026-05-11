"""Verify Alien Agent SSO DPoP requests.

Resource servers receive an RFC 9449 two-header pair from the agent:

    Authorization: DPoP <access_token>
    DPoP: <proof JWT>

`verify_dpop_request` walks the full RFC 9449 §4.3 checklist (plus the
§6.1 / RFC 7800 §3.1 cnf.jkt binding and the RFC 9068 §4 access-token
claim checks) and returns the human owner (`sub`) plus the agent's
DPoP key thumbprint (`jkt`) on success.

Python port of `@alien-id/sso-agent-id`.
"""

from alien_sso_agent_id.jwks import DEFAULT_SSO_BASE_URL, fetch_alien_jwks
from alien_sso_agent_id.types import (
    JWK,
    JWKS,
    DPoPJtiStore,
    VerifyDPoPFailure,
    VerifyDPoPOptions,
    VerifyDPoPResult,
    VerifyDPoPSuccess,
)
from alien_sso_agent_id.verify import verify_dpop_request

__all__ = [
    "DEFAULT_SSO_BASE_URL",
    "DPoPJtiStore",
    "JWK",
    "JWKS",
    "VerifyDPoPFailure",
    "VerifyDPoPOptions",
    "VerifyDPoPResult",
    "VerifyDPoPSuccess",
    "fetch_alien_jwks",
    "verify_dpop_request",
]
