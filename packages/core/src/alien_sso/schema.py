"""Response schemas for the Alien SSO OAuth2 endpoints.

Plain dataclasses (no pydantic) — the fields and shapes mirror the JS Zod
schemas in `packages/core/src/schema.ts`. We validate just enough at the
edges to fail fast with a useful error.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Union


class PollStatus(str, Enum):
    PENDING = "pending"
    AUTHORIZED = "authorized"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True)
class AuthorizeResponse:
    deep_link: str
    polling_code: str
    expired_at: int
    # RFC 6749 §10.12: opaque CSPRNG value the caller MUST persist and
    # echo back to `poll_auth(expected_state=...)` so the client can
    # detect a forged authorization response.
    state: str = ""

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "AuthorizeResponse":
        return cls(
            deep_link=_require_str(data, "deep_link"),
            polling_code=_require_str(data, "polling_code"),
            expired_at=_require_int(data, "expired_at"),
        )


@dataclass(frozen=True)
class PollResponse:
    status: PollStatus
    authorization_code: Optional[str] = None
    # RFC 9207 §2: when the AS advertises
    # `authorization_response_iss_parameter_supported: true` in its
    # metadata, it MUST include `iss` on every authorization response.
    # The Client MUST then verify that the value identifies the expected
    # issuer to detect AS-mix-up. We carry the value through the schema
    # so `client.poll_auth` can perform the comparison.
    iss: Optional[str] = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "PollResponse":
        status = PollStatus(_require_str(data, "status"))
        code = data.get("authorization_code")
        if code is not None and not isinstance(code, str):
            raise ValueError("authorization_code must be a string")
        iss_raw = data.get("iss")
        if iss_raw is not None and not isinstance(iss_raw, str):
            raise ValueError("iss must be a string")
        return cls(status=status, authorization_code=code, iss=iss_raw)


@dataclass(frozen=True)
class TokenResponse:
    access_token: str
    token_type: str
    # RFC 6749 §5.1: `expires_in` is RECOMMENDED, not REQUIRED — AS responses
    # may omit it. `refresh_token` is OPTIONAL on the auth-code response and
    # §6 explicitly permits the AS to omit it on a refresh response (in which
    # case the existing refresh_token remains valid). Treating either as
    # mandatory at the parser layer would crash on RFC-compliant responses.
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None  # not returned on refresh_token grant

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TokenResponse":
        token_type = _require_str(data, "token_type")
        # RFC 6750 §4 / RFC 6749 §5.1: token_type identifies the scheme
        # the AS expects on resource requests. This client only ever
        # constructs `Authorization: Bearer <access_token>`, so an AS
        # response advertising any other scheme (e.g. `DPoP`, `MAC`) is
        # a contract mismatch and MUST be rejected up-front rather than
        # silently downgraded into a Bearer call. Comparison is
        # case-insensitive per RFC 6749 §5.1.
        if token_type.lower() != "bearer":
            raise ValueError(
                f"unsupported token_type {token_type!r}; "
                f"this client only supports Bearer (RFC 6750)"
            )
        expires_in_raw = data.get("expires_in")
        expires_in: Optional[int] = None
        if expires_in_raw is not None:
            if not isinstance(expires_in_raw, int) or isinstance(expires_in_raw, bool):
                raise ValueError("expires_in must be an integer")
            expires_in = expires_in_raw
        refresh_token_raw = data.get("refresh_token")
        if refresh_token_raw is not None and not isinstance(refresh_token_raw, str):
            raise ValueError("refresh_token must be a string")
        return cls(
            access_token=_require_str(data, "access_token"),
            token_type=token_type,
            expires_in=expires_in,
            refresh_token=refresh_token_raw,
            id_token=data.get("id_token"),
        )


@dataclass(frozen=True)
class UserInfoResponse:
    sub: str
    # `/oauth/userinfo` returns the AT's client_id here so RP-side
    # consumers can confirm the token was issued for them.
    aud: Optional[str] = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "UserInfoResponse":
        return cls(sub=_require_str(data, "sub"), aud=data.get("aud"))


@dataclass(frozen=True)
class TokenInfo:
    """Standard OIDC claims, parsed from a JWT payload."""

    iss: str
    sub: str
    aud: Union[str, list[str]]
    exp: int
    iat: int
    # RFC 9068 §2.2: REQUIRED on AT, absent on id_token — optional here so
    # both shapes parse.
    client_id: Optional[str] = None
    jti: Optional[str] = None
    nonce: Optional[str] = None
    auth_time: Optional[int] = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TokenInfo":
        aud = data.get("aud")
        if not isinstance(aud, (str, list)):
            raise ValueError("aud must be a string or list of strings")
        return cls(
            iss=_require_str(data, "iss"),
            sub=_require_str(data, "sub"),
            aud=aud,
            exp=_require_int(data, "exp"),
            iat=_require_int(data, "iat"),
            client_id=data.get("client_id"),
            jti=data.get("jti"),
            nonce=data.get("nonce"),
            auth_time=data.get("auth_time"),
        )


def _require_str(d: dict[str, Any], key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str):
        raise ValueError(f"{key} must be a string")
    return v


def _require_int(d: dict[str, Any], key: str) -> int:
    v = d.get(key)
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"{key} must be an integer")
    return v
