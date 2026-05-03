"""Solana SSO request/response shapes.

Mirrors `packages/solanaCore/src/schema.ts` from the JS SDK.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class SolanaPollStatus(str, Enum):
    PENDING = "pending"
    AUTHORIZED = "authorized"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True)
class SolanaLinkRequest:
    solana_address: str

    def to_json(self) -> dict[str, Any]:
        return {"solana_address": self.solana_address}


@dataclass(frozen=True)
class SolanaLinkResponse:
    deep_link: str
    polling_code: str
    expired_at: int

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "SolanaLinkResponse":
        return cls(
            deep_link=_require_str(data, "deep_link"),
            polling_code=_require_str(data, "polling_code"),
            expired_at=_require_int(data, "expired_at"),
        )


@dataclass(frozen=True)
class SolanaPollRequest:
    polling_code: str

    def to_json(self) -> dict[str, Any]:
        return {"polling_code": self.polling_code}


@dataclass(frozen=True)
class SolanaPollResponse:
    status: SolanaPollStatus
    oracle_signature: Optional[str] = None
    oracle_public_key: Optional[str] = None
    solana_address: Optional[str] = None
    timestamp: Optional[int] = None
    session_address: Optional[str] = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "SolanaPollResponse":
        return cls(
            status=SolanaPollStatus(_require_str(data, "status")),
            oracle_signature=data.get("oracle_signature"),
            oracle_public_key=data.get("oracle_public_key"),
            solana_address=data.get("solana_address"),
            timestamp=data.get("timestamp"),
            session_address=data.get("session_address"),
        )


@dataclass(frozen=True)
class SolanaAttestationRequest:
    solana_address: str

    def to_json(self) -> dict[str, Any]:
        return {"solana_address": self.solana_address}


@dataclass(frozen=True)
class SolanaAttestationResponse:
    session_address: str

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "SolanaAttestationResponse":
        return cls(session_address=_require_str(data, "session_address"))


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
