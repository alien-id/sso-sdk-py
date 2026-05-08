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

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "PollResponse":
        status = PollStatus(_require_str(data, "status"))
        code = data.get("authorization_code")
        if code is not None and not isinstance(code, str):
            raise ValueError("authorization_code must be a string")
        return cls(status=status, authorization_code=code)


@dataclass(frozen=True)
class TokenResponse:
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    id_token: Optional[str] = None  # not returned on refresh_token grant

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TokenResponse":
        return cls(
            access_token=_require_str(data, "access_token"),
            token_type=_require_str(data, "token_type"),
            expires_in=_require_int(data, "expires_in"),
            refresh_token=_require_str(data, "refresh_token"),
            id_token=data.get("id_token"),
        )


@dataclass(frozen=True)
class UserInfoResponse:
    sub: str

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "UserInfoResponse":
        return cls(sub=_require_str(data, "sub"))


@dataclass(frozen=True)
class TokenInfo:
    """Standard OIDC claims, parsed from a JWT payload."""

    iss: str
    sub: str
    aud: Union[str, list[str]]
    exp: int
    iat: int
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
