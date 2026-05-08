"""Alien SSO OAuth2 PKCE client.

Python port of `@alien-id/sso`. The browser `localStorage`/`sessionStorage`
assumptions in the JS package are replaced with a pluggable `Storage` protocol
— see `alien_sso.storage` for the in-memory default and a disk-backed variant.
"""

from alien_sso.client import AlienSsoClient, AlienSsoClientConfig, NonceStore
from alien_sso.errors import (
    AlienSsoError,
    AuthorizeError,
    PollError,
    RefreshError,
    TokenExchangeError,
    UnauthorizedError,
)
from alien_sso.schema import (
    AuthorizeResponse,
    PollResponse,
    PollStatus,
    TokenInfo,
    TokenResponse,
    UserInfoResponse,
)
from alien_sso.storage import FileStorage, MemoryStorage, Storage

__all__ = [
    "AlienSsoClient",
    "AlienSsoClientConfig",
    "AlienSsoError",
    "AuthorizeError",
    "AuthorizeResponse",
    "FileStorage",
    "MemoryStorage",
    "NonceStore",
    "PollError",
    "PollResponse",
    "PollStatus",
    "RefreshError",
    "Storage",
    "TokenExchangeError",
    "TokenInfo",
    "TokenResponse",
    "UnauthorizedError",
    "UserInfoResponse",
]
