"""Exception types used by the SSO client.

The JS package throws plain `Error` everywhere; we promote the meaningful
distinctions (auth failure, refresh failure, 401, …) to dedicated subclasses
so callers can `except` precisely.
"""

from __future__ import annotations


class AlienSsoError(Exception):
    """Base class for all SSO client errors."""


class AuthorizeError(AlienSsoError):
    """Raised when /oauth/authorize returns a non-2xx response."""


class PollError(AlienSsoError):
    """Raised when /oauth/poll returns a non-2xx response."""


class TokenExchangeError(AlienSsoError):
    """Raised when the authorization-code → token exchange fails."""


class RefreshError(AlienSsoError):
    """Raised when the refresh-token → token exchange fails. Tokens are cleared."""


class UnauthorizedError(AlienSsoError):
    """Raised when the userinfo endpoint returns 401 and refresh failed (or wasn't tried)."""
