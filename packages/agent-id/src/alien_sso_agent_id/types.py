from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, TypedDict, Union


class JWK(TypedDict, total=False):
    kty: str
    kid: str
    n: str
    e: str
    alg: str
    use: str


class JWKS(TypedDict):
    keys: list[JWK]


class OwnerBinding(TypedDict, total=False):
    payload: dict[str, Any]
    payloadHash: str
    signature: str


@dataclass(frozen=True)
class VerifyOptions:
    """Options for `verify_agent_token`.

    max_age_ms: Maximum token age in milliseconds. Default: 300000 (5 min).
    clock_skew_ms: Allowed clock skew in milliseconds for future-dated tokens.
        Default: 30000 (30 sec).
    """

    max_age_ms: int = 5 * 60 * 1000
    clock_skew_ms: int = 30 * 1000


@dataclass(frozen=True)
class VerifyOwnerOptions:
    """Options for `verify_agent_token_with_owner`.

    `expected_audience` is REQUIRED. Per RFC 7519 §4.1.3 / OIDC §3.1.3.7
    the consuming Client MUST identify itself in the id_token's aud
    claim, and that identity is the Client's own OAuth ``client_id``
    (its ``providerAddress``) — the library cannot guess it because each
    integrating app registers a distinct value.

    `expected_issuer` is optional and defaults to the Alien SSO
    production endpoint (``DEFAULT_SSO_BASE_URL``). Override only when
    verifying tokens from a non-default deployment (staging, self-host,
    integration tests).

    `expected_audience` may be a single string or a list.

    `trusted_audiences` is the OIDC §3.1.3.7 step 3 trust set: when the
    id_token's aud is multi-valued, every entry MUST be in this set.
    Defaults to the expected_audience(s) when omitted.
    """

    jwks: JWKS
    expected_audience: Union[str, list[str]]
    expected_issuer: Optional[str] = None
    max_age_ms: int = 5 * 60 * 1000
    clock_skew_ms: int = 30 * 1000
    trusted_audiences: Optional[frozenset[str]] = None


@dataclass(frozen=True)
class VerifySuccess:
    fingerprint: str
    public_key_pem: str
    owner: Optional[str]
    owner_verified: bool
    timestamp: int
    nonce: str
    ok: bool = True


@dataclass(frozen=True)
class VerifyOwnerSuccess:
    fingerprint: str
    public_key_pem: str
    owner: str
    timestamp: int
    nonce: str
    issuer: str
    owner_verified: bool = True
    ok: bool = True


@dataclass(frozen=True)
class VerifyFailure:
    error: str
    ok: bool = False


VerifyResult = Union[VerifySuccess, VerifyOwnerSuccess, VerifyFailure]


@dataclass(frozen=True)
class AgentIdentity:
    """Compact, friendly result type for callers that only care about identity."""

    fingerprint: str
    owner: Optional[str]
    public_key_pem: str
    owner_verified: bool
