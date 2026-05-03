"""Verify Alien Agent ID tokens.

The agent calls your service with `Authorization: AgentID <base64url-json>`.
The token is self-contained — it carries the agent's Ed25519 public key, so
verification needs no prior key registration. Owner-bound tokens additionally
carry the SSO `ownerBinding` and `idToken`, verified against Alien SSO's JWKS
to prove the human owner actually authorized this agent.

Python port of `@alien-id/sso-agent-id`.
"""

from alien_sso_agent_id.jwks import fetch_alien_jwks
from alien_sso_agent_id.types import (
    AgentIdentity,
    OwnerBinding,
    VerifyFailure,
    VerifyOwnerOptions,
    VerifyOwnerSuccess,
    VerifyOptions,
    VerifyResult,
    VerifySuccess,
    JWK,
    JWKS,
)
from alien_sso_agent_id.verify import (
    verify_agent_request,
    verify_agent_request_with_owner,
    verify_agent_token,
    verify_agent_token_with_owner,
)

__all__ = [
    "AgentIdentity",
    "JWK",
    "JWKS",
    "OwnerBinding",
    "VerifyFailure",
    "VerifyOptions",
    "VerifyOwnerOptions",
    "VerifyOwnerSuccess",
    "VerifyResult",
    "VerifySuccess",
    "fetch_alien_jwks",
    "verify_agent_request",
    "verify_agent_request_with_owner",
    "verify_agent_token",
    "verify_agent_token_with_owner",
]
