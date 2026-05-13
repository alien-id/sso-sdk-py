from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Optional, Protocol, TypedDict, Union


class JWK(TypedDict, total=False):
    kty: str
    kid: str
    n: str
    e: str
    alg: str
    use: str


class JWKS(TypedDict):
    keys: list[JWK]


class DPoPJtiStore(Protocol):
    """Pluggable replay-protection store for the DPoP proof's `jti` claim
    (RFC 9449 §11.1). Default in-memory store is single-process — pass a
    Redis/Memcached-backed implementation to share replay state across
    resource-server instances."""

    def has(self, jti: str) -> bool: ...
    def add(self, jti: str, iat: int) -> None: ...


@dataclass(frozen=True)
class VerifyDPoPOptions:
    """Options for `verify_dpop_request`.

    `jwks` is the pre-fetched SSO JWKS (RFC 9068 §4 access-token signature key).

    `expected_issuer` defaults to Alien SSO's production endpoint when omitted
    (RFC 7519 §4.1.1).

    `expected_audience` defaults to `expected_issuer` (the federated-audience
    pattern: the Alien SSO mints `aud = [client_id, issuer]` so any agent-id
    token presented to any Alien-aware RS satisfies the default check). Pass an
    explicit string to narrow to a specific OAuth `client_id` or RFC 8707
    resource indicator. Pass `False` to skip the audience check entirely
    (test fixtures only — discouraged in production).

    `proof_max_age_sec` is the DPoP proof freshness window (RFC 9449 §4.3 step 11).
    Default: 30.

    `clock_skew_sec` is applied to access_token `exp`. Default: 30.

    `jti_store` is the replay-protection store for the DPoP proof's `jti`.
    Default: an in-memory dict scoped to the verifier's import (single-process).
    Inject a shared store for multi-instance deployments.
    """

    jwks: JWKS
    expected_issuer: Optional[str] = None
    expected_audience: Union[str, Literal[False], None] = None
    proof_max_age_sec: int = 30
    clock_skew_sec: int = 30
    jti_store: Optional[DPoPJtiStore] = None


@dataclass(frozen=True)
class VerifyDPoPSuccess:
    """Successful verify_dpop_request result.

    `sub` is the access_token's `sub` claim (the human owner).
    `jkt` is the RFC 7638 thumbprint of the agent's DPoP key (matches AT `cnf.jkt`).
    `access_token_claims` is the decoded access_token claim set (RFC 9068 §2.2).
    `proof_claims` is the decoded DPoP proof claim set (RFC 9449 §4.2).
    """

    sub: str
    jkt: str
    access_token_claims: dict[str, Any]
    proof_claims: dict[str, Any]
    ok: bool = True


@dataclass(frozen=True)
class VerifyDPoPFailure:
    """Failed verify_dpop_request result.

    `code` is a machine-readable error label aligned with RFC 9449 / RFC 9068
    / RFC 6750 categories (e.g. `invalid_token`, `bad_proof_signature`,
    `jkt_mismatch`). Stable across releases; new values may be added.

    `error` is a human-readable error message.
    """

    code: str
    error: str
    ok: bool = False


VerifyDPoPResult = VerifyDPoPSuccess | VerifyDPoPFailure
