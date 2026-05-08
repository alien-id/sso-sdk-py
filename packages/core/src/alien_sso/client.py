"""AlienSsoClient — Python port of `packages/core/src/client.ts`.

Async-first: all HTTP methods are `async def` and use `httpx.AsyncClient`.
Browser `localStorage` / `sessionStorage` is replaced by the `Storage`
protocol — defaults to `MemoryStorage`. Tokens, refresh tokens, expiry, and
the PKCE code verifier all go through the same Storage instance.

Concurrent refresh attempts coalesce into a single network call via an
`asyncio.Lock` + cached future (mirrors the JS singleton-promise pattern).

Errors are typed (`AuthorizeError`, `PollError`, `TokenExchangeError`,
`RefreshError`, `UnauthorizedError`).
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, TypeVar
from urllib.parse import urljoin

import httpx

from alien_sso._pkce import generate_code_challenge, generate_code_verifier
from alien_sso.errors import (
    AuthorizeError,
    PollError,
    RefreshError,
    TokenExchangeError,
    UnauthorizedError,
)
from alien_sso.schema import (
    AuthorizeResponse,
    PollResponse,
    TokenInfo,
    TokenResponse,
    UserInfoResponse,
)
from alien_sso.storage import MemoryStorage, Storage

DEFAULT_SSO_BASE_URL = "https://sso.alien.com"
DEFAULT_POLLING_INTERVAL = 5.0  # seconds, used by callers driving the poll loop

_STORAGE_KEY = "alien-sso_"
_KEY_ACCESS = _STORAGE_KEY + "access_token"
_KEY_ID_TOKEN = _STORAGE_KEY + "id_token"
_KEY_REFRESH = _STORAGE_KEY + "refresh_token"
_KEY_EXPIRY = _STORAGE_KEY + "token_expiry"
_KEY_VERIFIER = _STORAGE_KEY + "code_verifier"


T = TypeVar("T")


@dataclass(frozen=True)
class AlienSsoClientConfig:
    sso_base_url: str
    provider_address: str
    polling_interval: float = DEFAULT_POLLING_INTERVAL


class AlienSsoClient:
    """Async Alien SSO client.

    Lifecycle:
        1. `await generate_deeplink()` → returns deep_link + polling_code.
        2. Show the deep_link as a QR code.
        3. `await poll_auth(polling_code)` until status == 'authorized'.
        4. `await exchange_token(authorization_code)` → access + id + refresh.
        5. `await verify_auth()` to fetch userinfo (auto-refreshes on 401).
        6. `logout()` to clear stored credentials (sync — no network).

    Use as an async context manager when you don't pass your own `http_client`:

        async with AlienSsoClient(config) as client:
            await client.generate_deeplink()
    """

    def __init__(
        self,
        config: AlienSsoClientConfig,
        *,
        storage: Optional[Storage] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        if not config.sso_base_url:
            raise ValueError("sso_base_url is required")
        if not config.provider_address:
            raise ValueError("provider_address is required")
        self.config = config
        self.sso_base_url = config.sso_base_url
        self.provider_address = config.provider_address
        self.polling_interval = config.polling_interval
        self._storage: Storage = storage or MemoryStorage()
        self._http = http_client or httpx.AsyncClient(timeout=10.0)
        self._owns_http = http_client is None
        # Coalesce concurrent refresh attempts (mirrors the JS singleton promise).
        self._refresh_lock = asyncio.Lock()
        self._refresh_future: Optional["asyncio.Future[TokenResponse]"] = None

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AlienSsoClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # ─── OAuth2 endpoints ───────────────────────────────────────────────

    async def generate_deeplink(self) -> AuthorizeResponse:
        """GET /oauth/authorize?response_mode=json — start a PKCE flow."""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        self._storage.set(_KEY_VERIFIER, verifier)

        params = {
            "response_type": "code",
            "response_mode": "json",
            "client_id": self.provider_address,
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        resp = await self._http.get(self._url("/oauth/authorize"), params=params)
        if resp.status_code >= 400:
            raise AuthorizeError(_describe_error(resp, "Authorize failed"))
        return AuthorizeResponse.from_json(resp.json())

    async def poll_auth(self, polling_code: str) -> PollResponse:
        """POST /oauth/poll — check whether the user has authorized yet."""
        resp = await self._http.post(
            self._url("/oauth/poll"),
            json={"polling_code": polling_code},
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code >= 400:
            raise PollError(f"Poll failed: {resp.reason_phrase}")
        return PollResponse.from_json(resp.json())

    async def exchange_token(self, authorization_code: str) -> TokenResponse:
        """POST /oauth/token (grant_type=authorization_code).

        Stores access_token, id_token (if present), refresh_token, and expiry.
        Clears the PKCE verifier afterwards.
        """
        verifier = self._storage.get(_KEY_VERIFIER)
        if not verifier:
            raise TokenExchangeError("Missing code verifier.")

        body = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "client_id": self.provider_address,
            "code_verifier": verifier,
        }
        resp = await self._http.post(
            self._url("/oauth/token"),
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code >= 400:
            raise TokenExchangeError(_describe_error(resp, "Token exchange failed"))
        token = TokenResponse.from_json(resp.json())
        self._store_tokens(token)
        self._storage.delete(_KEY_VERIFIER)
        return token

    async def verify_auth(self) -> Optional[UserInfoResponse]:
        """GET /oauth/userinfo — auto-refreshes on 401 if a refresh token exists."""
        return await self.with_auto_refresh(self._verify_auth_once)

    async def _verify_auth_once(self) -> Optional[UserInfoResponse]:
        access = self.get_access_token()
        if not access:
            return None
        resp = await self._http.get(
            self._url("/oauth/userinfo"),
            headers={"Authorization": f"Bearer {access}"},
        )
        if resp.status_code == 401:
            raise UnauthorizedError("Unauthorized")
        if resp.status_code >= 400:
            return None
        return UserInfoResponse.from_json(resp.json())

    async def refresh_access_token(self) -> TokenResponse:
        """POST /oauth/token (grant_type=refresh_token).

        Concurrent callers coalesce — only one network request fires; the rest
        await the same future.
        """
        async with self._refresh_lock:
            if self._refresh_future is not None and not self._refresh_future.done():
                future = self._refresh_future
            else:
                future = asyncio.get_running_loop().create_future()
                self._refresh_future = future
                # Fire and forget — `future` carries the result.
                asyncio.create_task(self._do_refresh_into(future))
        return await future

    async def _do_refresh_into(self, future: "asyncio.Future[TokenResponse]") -> None:
        try:
            token = await self._do_refresh()
        except BaseException as e:
            future.set_exception(e)
            return
        future.set_result(token)

    async def _do_refresh(self) -> TokenResponse:
        refresh = self.get_refresh_token()
        if not refresh:
            raise RefreshError("No refresh token available")

        resp = await self._http.post(
            self._url("/oauth/token"),
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": self.provider_address,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code >= 400:
            self.logout()  # nuke stale tokens
            raise RefreshError(_describe_error(resp, "Token refresh failed"))
        token = TokenResponse.from_json(resp.json())
        self._store_tokens(token)
        return token

    async def with_auto_refresh(
        self, fn: Callable[[], Awaitable[T]], max_retries: int = 1
    ) -> T:
        """Run `fn`; if it raises `UnauthorizedError`, refresh and retry once."""
        try:
            return await fn()
        except UnauthorizedError:
            if max_retries <= 0 or not self.has_refresh_token():
                raise
            await self.refresh_access_token()
            return await fn()

    # ─── Token / storage helpers (sync — no I/O) ────────────────────────

    def get_access_token(self) -> Optional[str]:
        return self._storage.get(_KEY_ACCESS)

    def get_id_token(self) -> Optional[str]:
        return self._storage.get(_KEY_ID_TOKEN)

    def get_refresh_token(self) -> Optional[str]:
        return self._storage.get(_KEY_REFRESH)

    def has_refresh_token(self) -> bool:
        return self.get_refresh_token() is not None

    def get_subject(self) -> Optional[str]:
        info = self.get_auth_data()
        return info.sub if info else None

    def get_auth_data(self) -> Optional[TokenInfo]:
        """Decode + validate the JWT (id_token preferred, falls back to access).

        Mirrors the JS `getAuthData`: requires header alg=RS256 + typ=JWT, and
        the audience must include `provider_address`. No signature verification
        — that's the SSO server's job at issuance time.
        """
        token = self.get_id_token() or self.get_access_token()
        if not token:
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception:
            return None
        if header.get("alg") != "RS256" or header.get("typ") != "JWT":
            return None
        try:
            payload = TokenInfo.from_json(json.loads(_b64url_decode(parts[1])))
        except Exception:
            return None
        aud_list = payload.aud if isinstance(payload.aud, list) else [payload.aud]
        if self.provider_address not in aud_list:
            return None
        return payload

    def is_token_expired(self) -> bool:
        info = self.get_auth_data()
        if info is None:
            return True
        return time.time() > info.exp

    def is_access_token_expired(self) -> bool:
        """True if the stored access token will expire in the next 5 minutes."""
        raw = self._storage.get(_KEY_EXPIRY)
        if not raw:
            return True
        try:
            expiry_ms = int(raw)
        except ValueError:
            return True
        now_ms = int(time.time() * 1000)
        buffer_ms = 5 * 60 * 1000
        return now_ms >= expiry_ms - buffer_ms

    def logout(self) -> None:
        """Clear every key this client owns. Idempotent. Synchronous — no I/O."""
        for key in (_KEY_ACCESS, _KEY_ID_TOKEN, _KEY_REFRESH, _KEY_EXPIRY, _KEY_VERIFIER):
            self._storage.delete(key)

    # ─── Internals ──────────────────────────────────────────────────────

    def _store_tokens(self, token: TokenResponse) -> None:
        self._storage.set(_KEY_ACCESS, token.access_token)
        if token.id_token:
            self._storage.set(_KEY_ID_TOKEN, token.id_token)
        self._storage.set(_KEY_REFRESH, token.refresh_token)
        expiry_ms = int(time.time() * 1000) + token.expires_in * 1000
        self._storage.set(_KEY_EXPIRY, str(expiry_ms))

    def _url(self, path: str) -> str:
        # Match `new URL(path, base)` — preserves the path portion of base_url.
        base = self.sso_base_url
        if not base.endswith("/"):
            base = base + "/"
        return urljoin(base, path.lstrip("/"))


def _describe_error(resp: httpx.Response, prefix: str) -> str:
    try:
        body = resp.json()
        if isinstance(body, dict):
            msg = body.get("error_description") or body.get("error")
            if isinstance(msg, str):
                return f"{prefix}: {msg}"
    except Exception:
        pass
    return f"{prefix}: {resp.reason_phrase or resp.status_code}"


def _b64url_decode(s: str) -> str:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8")
