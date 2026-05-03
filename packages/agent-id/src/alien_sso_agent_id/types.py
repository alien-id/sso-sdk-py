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
    """Options for `verify_agent_token_with_owner`. Adds a required JWKS."""

    jwks: JWKS
    max_age_ms: int = 5 * 60 * 1000
    clock_skew_ms: int = 30 * 1000


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
    owner_proof_verified: bool
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
